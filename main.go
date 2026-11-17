package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SessionTarget struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
}

type StatusMessage struct {
	State   string  `json:"state"`
	Message string  `json:"message,omitempty"`
	Time    float64 `json:"time"`
}

var (
	settings       *Settings
	store          *TodusStore
	allow          *Allowlist
	activeSessions atomic.Int64
	sessionsWg     sync.WaitGroup
)

func publishStatus(sessionID, state, message string) {
	status := StatusMessage{State: state, Message: message, Time: float64(time.Now().UnixNano()) / 1e9}
	raw, _ := json.Marshal(status)
	if !store.Put(StatusKey(sessionID), raw) {
		slog.Warn("publishStatus put falló", "session", shortID(sessionID), "state", state)
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func waitForWindow(ctx context.Context, sessionID, direction string, sequence uint64, stopCh <-chan struct{}, lastAck *uint64) bool {
	ticker := time.NewTicker(settings.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-stopCh:
			return false
		default:
		}
		rawAck := store.Get(AckKey(direction, sessionID), 0)
		if rawAck != nil {
			val := DecodeCounter(rawAck)
			for {
				old := atomic.LoadUint64(lastAck)
				if val <= old {
					break
				}
				if atomic.CompareAndSwapUint64(lastAck, old, val) {
					break
				}
			}
		}
		if sequence-atomic.LoadUint64(lastAck) < uint64(settings.WindowSize) {
			return true
		}
		if store.Get(CloseKey(sessionID), 0) != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-stopCh:
			return false
		case <-ticker.C:
		}
	}
}

type UDPFlow struct {
	conn         *net.UDPConn
	replyHost    string
	replyPort    uint16
	responses    chan<- UDPPacket
	stopCh       <-chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	lastActivity int64
}

func NewUDPFlow(host string, port uint16, responses chan<- UDPPacket, stopCh <-chan struct{}) (*UDPFlow, error) {
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	f := &UDPFlow{
		conn: conn, replyHost: raddr.IP.String(), replyPort: uint16(raddr.Port),
		responses: responses, stopCh: stopCh, closed: make(chan struct{}),
		lastActivity: time.Now().UnixNano(),
	}
	go f.reader()
	return f, nil
}

func (f *UDPFlow) Send(payload []byte) error {
	atomic.StoreInt64(&f.lastActivity, time.Now().UnixNano())
	_, err := f.conn.Write(payload)
	return err
}

func (f *UDPFlow) reader() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-f.stopCh:
			return
		case <-f.closed:
			return
		default:
		}
		f.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := f.conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		atomic.StoreInt64(&f.lastActivity, time.Now().UnixNano())
		pkt := UDPPacket{Host: f.replyHost, Port: f.replyPort, Payload: make([]byte, n)}
		copy(pkt.Payload, buf[:n])
		select {
		case f.responses <- pkt:
		case <-time.After(200 * time.Millisecond):
			// FIX: pérdida contabilizada (antes se descartaba en silencio)
			slog.Debug("udp response channel lleno, paquete descartado", "host", pkt.Host, "port", pkt.Port)
		case <-f.stopCh:
			return
		case <-f.closed:
			return
		}
	}
}

func (f *UDPFlow) Close()                  { f.closeOnce.Do(func() { close(f.closed); f.conn.Close() }) }
func (f *UDPFlow) LastActivity() time.Time { return time.Unix(0, atomic.LoadInt64(&f.lastActivity)) }

func udpDownlinkPublisher(ctx context.Context, sessionID string, responses <-chan UDPPacket, stopCh <-chan struct{}) {
	var seq uint64
	sem := make(chan struct{}, settings.UDPUploadWorkers)
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		store.Put(FinKey("s2c", sessionID), EncodeCounter(seq))
	}()
	for {
		var first UDPPacket
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			select {
			case first = <-responses:
			default:
				return
			}
		case pkt, ok := <-responses:
			if !ok {
				return
			}
			first = pkt
		case <-time.After(settings.UDPPollInterval):
			continue
		}
		batch := []UDPPacket{first}
		bbytes := len(first.Payload)
		deadline := time.Now().Add(settings.UDPBatchDelayMS)
		for len(batch) < settings.UDPBatchCount && bbytes < settings.UDPBatchMaxBytes {
			rem := time.Until(deadline)
			if rem <= 0 {
				break
			}
			select {
			case it, ok := <-responses:
				if !ok {
					break
				}
				batch = append(batch, it)
				bbytes += len(it.Payload)
			case <-time.After(rem):
				break
			}
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(s uint64, recs []UDPPacket) {
			defer func() { <-sem; wg.Done() }()
			body, _ := EncodeUDPBatch(s, recs)
			// FIX: registrar fallos de Put (antes se ignoraban)
			if !store.Put(UDPDataKey("s2c", sessionID, s), body) {
				slog.Warn("udp publisher put falló", "session", shortID(sessionID), "seq", s)
			}
		}(seq, batch)
		seq++
	}
}

func handleUDPSession(ctx context.Context, sessionID string) {
	stopCh := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(stopCh) }) }
	// FIX: buffer reducido de UDPMaxFlows*64 a *4 para evitar reservas absurdas
	// de memoria (hasta ~16GB en el peor caso teórico con los máximos).
	responses := make(chan UDPPacket, settings.UDPMaxFlows*4)
	flows := make(map[string]*UDPFlow)
	var fmu sync.Mutex
	var pubWg sync.WaitGroup
	pubWg.Add(1)
	go func() {
		defer pubWg.Done()
		udpDownlinkPublisher(ctx, sessionID, responses, stopCh)
	}()
	publishStatus(sessionID, "ready", "")
	slog.Info("udp session iniciada", "session", shortID(sessionID))
	var seq uint64
	lastAct := time.Now()
	closeSeen := false
	defer func() {
		fmu.Lock()
		for _, f := range flows {
			f.Close()
		}
		fmu.Unlock()
		stop()
		pubWg.Wait()
		publishStatus(sessionID, "closed", "")
		slog.Info("udp session cerrada", "session", shortID(sessionID), "seq", seq, "flows", len(flows))
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if store.Get(CloseKey(sessionID), 0) != nil {
			closeSeen = true
		}
		raw := store.Get(UDPDataKey("c2s", sessionID, seq), 0)
		if raw == nil {
			if next := store.Get(UDPDataKey("c2s", sessionID, seq+1), 0); next != nil {
				// FIX: avisar del salto en lugar de ocultarlo
				slog.Warn("udp salto de seq detectado", "session", shortID(sessionID), "seq", seq)
				seq++
				raw = next
			}
		}
		if raw == nil {
			if closeSeen {
				if fin := store.Get(FinKey("c2s", sessionID), 0); fin != nil && seq >= DecodeCounter(fin) {
					break
				}
			}
			if time.Since(lastAct) > 180*time.Second {
				slog.Info("udp session timeout inactividad", "session", shortID(sessionID))
				break
			}
			time.Sleep(settings.UDPPollInterval)
			continue
		}
		records, err := DecodeUDPBatch(raw, seq)
		if err == nil {
			if settings.DeleteAfterRead {
				store.Delete(UDPDataKey("c2s", sessionID, seq))
			}
			seq++
			for _, item := range records {
				// FIX: aplicar allowlist a destinos UDP
				if !allow.Allow(item.Host, int(item.Port)) {
					slog.Warn("udp destino bloqueado por allowlist", "session", shortID(sessionID), "host", item.Host, "port", item.Port)
					continue
				}
				fk := fmt.Sprintf("%s:%d", item.Host, item.Port)
				fmu.Lock()
				flow, ok := flows[fk]
				if !ok {
					flow, _ = NewUDPFlow(item.Host, item.Port, responses, stopCh)
					if flow != nil {
						flows[fk] = flow
					}
				}
				fmu.Unlock()
				if flow != nil {
					if flow.Send(item.Payload) == nil {
						lastAct = time.Now()
					}
				}
			}
		} else {
			// FIX: registrar errores de decode (antes se descartaba el lote en silencio)
			slog.Warn("udp decode batch error", "session", shortID(sessionID), "seq", seq, "err", err)
		}
	}
}

func handleTCPSession(ctx context.Context, sessionID string, target SessionTarget) {
	// FIX: aplicar allowlist antes de dial
	if !allow.Allow(target.Host, target.Port) {
		publishStatus(sessionID, "error", "destino no permitido por allowlist")
		slog.Warn("tcp destino bloqueado por allowlist", "session", shortID(sessionID), "host", target.Host, "port", target.Port)
		return
	}
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	remote, err := net.DialTimeout("tcp", addr, settings.ConnectTimeout)
	if err != nil {
		publishStatus(sessionID, "error", err.Error())
		slog.Warn("tcp dial falló", "session", shortID(sessionID), "addr", addr, "err", err)
		return
	}
	defer remote.Close()
	publishStatus(sessionID, "ready", "")
	slog.Info("tcp session iniciada", "session", shortID(sessionID), "addr", addr)

	stopCh := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(stopCh) }) }
	remoteFin := make(chan struct{})
	var rOnce sync.Once
	setFin := func() { rOnce.Do(func() { close(remoteFin) }) }
	var lastAct int64
	atomic.StoreInt64(&lastAct, time.Now().UnixNano())
	var lastAck uint64
	var upWg sync.WaitGroup
	upWg.Add(1)
	go func() {
		defer upWg.Done()
		defer setFin()
		var seq uint64
		buf := make([]byte, settings.ChunkSize)
		for {
			select {
			case <-ctx.Done():
				store.Put(FinKey("s2c", sessionID), EncodeCounter(seq))
				return
			case <-stopCh:
				store.Put(FinKey("s2c", sessionID), EncodeCounter(seq))
				return
			default:
			}
			remote.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, err := remote.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				// FIX: el bloque `if err != io.EOF {}` vacío del original se reemplaza
				// por un manejo explícito: EOF = cierre limpio (debug), otro = warn.
				if err == io.EOF {
					slog.Debug("tcp remote EOF", "session", shortID(sessionID), "seq", seq)
				} else {
					slog.Warn("tcp remote read error", "session", shortID(sessionID), "seq", seq, "err", err)
				}
				break
			}
			if n == 0 {
				break
			}
			if !waitForWindow(ctx, sessionID, "s2c", seq, stopCh, &lastAck) {
				break
			}
			if !store.Put(DataKey("s2c", sessionID, seq), EncodeFrame(seq, buf[:n])) {
				slog.Warn("tcp s2c put falló", "session", shortID(sessionID), "seq", seq)
				break
			}
			seq++
			atomic.StoreInt64(&lastAct, time.Now().UnixNano())
		}
		store.Put(FinKey("s2c", sessionID), EncodeCounter(seq))
	}()

	var seq uint64
	var sinceAck int
	lastAckTime := time.Now()
	clientFin := false
	defer func() {
		stop()
		remote.Close()
		upWg.Wait()
		publishStatus(sessionID, "closed", "")
		slog.Info("tcp session cerrada", "session", shortID(sessionID), "seq", seq)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if store.Get(CloseKey(sessionID), 0) != nil {
			break
		}
		raw := store.Get(DataKey("c2s", sessionID, seq), 0)
		if raw != nil {
			payload, err := DecodeFrame(raw, seq)
			if err == nil && len(payload) > 0 {
				// FIX: usar WriteTimeout (no ConnectTimeout) y registrar errores de write
				remote.SetWriteDeadline(time.Now().Add(settings.WriteTimeout))
				if _, werr := remote.Write(payload); werr != nil {
					slog.Warn("tcp remote write error", "session", shortID(sessionID), "seq", seq, "err", werr)
					break
				}
			} else if err != nil {
				slog.Warn("tcp decode frame error", "session", shortID(sessionID), "seq", seq, "err", err)
			}
			if settings.DeleteAfterRead {
				store.Delete(DataKey("c2s", sessionID, seq))
			}
			seq++
			sinceAck++
			atomic.StoreInt64(&lastAct, time.Now().UnixNano())
			if sinceAck >= settings.AckEvery || time.Since(lastAckTime) > time.Second {
				store.Put(AckKey("c2s", sessionID), EncodeCounter(seq))
				sinceAck = 0
				lastAckTime = time.Now()
			}
			continue
		}
		if fin := store.Get(FinKey("c2s", sessionID), 0); fin != nil && seq >= DecodeCounter(fin) && !clientFin {
			if sinceAck > 0 {
				store.Put(AckKey("c2s", sessionID), EncodeCounter(seq))
			}
			clientFin = true
			if tcp, ok := remote.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
		}
		remoteDone := false
		select {
		case <-remoteFin:
			remoteDone = true
		default:
		}
		if clientFin && remoteDone {
			break
		}
		last := time.Unix(0, atomic.LoadInt64(&lastAct))
		if time.Since(last) > time.Duration(math.Max(float64(settings.HTTPTimeout*3), 90*float64(time.Second))) {
			slog.Info("tcp session timeout inactividad", "session", shortID(sessionID))
			break
		}
		time.Sleep(settings.PollInterval)
	}
}

func handleSession(ctx context.Context, sessionID string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic en session", "session", shortID(sessionID), "panic", r)
			publishStatus(sessionID, "error", fmt.Sprintf("panic: %v", r))
		}
	}()
	var raw []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		raw = store.Get(TargetKey(sessionID), 0)
		if raw != nil {
			break
		}
		time.Sleep(settings.PollInterval)
	}
	if raw == nil {
		publishStatus(sessionID, "error", "target no encontrado")
		return
	}
	var t SessionTarget
	if err := json.Unmarshal(raw, &t); err != nil {
		publishStatus(sessionID, "error", "target inválido: "+err.Error())
		return
	}
	if t.Version != 2 {
		publishStatus(sessionID, "error", fmt.Sprintf("versión no soportada: %d", t.Version))
		return
	}
	// Deadline por sesión: asegura no agotar el límite de 6h de GitHub Actions
	// en una sola sesión. Hijo del ctx global para que SIGTERM cancele todo.
	sessionCtx, cancel := context.WithTimeout(ctx, settings.SessionMaxDuration)
	defer cancel()
	switch t.Mode {
	case "udp":
		handleUDPSession(sessionCtx, sessionID)
	case "tcp":
		handleTCPSession(sessionCtx, sessionID, t)
	default:
		publishStatus(sessionID, "error", "modo desconocido: "+t.Mode)
	}
}

// seenSet es un conjunto acotado con TTL para evitar la fuga de memoria
// del `seen` map original del worker, que crecía indefinidamente.
type seenSet struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

func newSeenSet(ttl time.Duration) *seenSet {
	return &seenSet{entries: make(map[string]time.Time), ttl: ttl}
}

func (s *seenSet) add(id string) {
	s.mu.Lock()
	s.entries[id] = time.Now()
	s.mu.Unlock()
}

func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	_, ok := s.entries[id]
	s.mu.Unlock()
	return ok
}

// sweep elimina entradas más antiguas que TTL. Lo llama el worker periódicamente.
func (s *seenSet) sweep() {
	s.mu.Lock()
	cutoff := time.Now().Add(-s.ttl)
	for id, t := range s.entries {
		if t.Before(cutoff) {
			delete(s.entries, id)
		}
	}
	s.mu.Unlock()
}

func worker(ctx context.Context) {
	active := make(map[string]struct{})
	var lock sync.Mutex
	sem := make(chan struct{}, settings.MaxSessions)
	// FIX: seen acotado con TTL, en lugar del mapa que crecía sin límite
	seen := newSeenSet(settings.SessionMaxDuration * 2)
	sweepTicker := time.NewTicker(5 * time.Minute)
	defer sweepTicker.Stop()
	for {
		// Reaccionar a shutdown y sweep periódico
		select {
		case <-ctx.Done():
			slog.Info("worker detenido (ctx cancelado)")
			return
		case <-sweepTicker.C:
			seen.sweep()
		default:
		}

		rateLimited := false
		for slot := 0; slot < 4; slot++ {
			data, status := store.GetWithStatus(QueueKey(slot), 0)
			if data == nil {
				if status == StatusRateLimited {
					rateLimited = true
				}
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				id := strings.TrimSpace(line)
				if id == "" {
					continue
				}
				lock.Lock()
				if seen.has(id) || len(active) >= settings.MaxSessions {
					lock.Unlock()
					continue
				}
				active[id] = struct{}{}
				seen.add(id)
				lock.Unlock()
				if store.Get(StatusKey(id), 0) != nil {
					lock.Lock()
					delete(active, id)
					lock.Unlock()
					continue
				}
				sem <- struct{}{}
				activeSessions.Add(1)
				sessionsWg.Add(1)
				go func(sID string) {
					defer func() {
						activeSessions.Add(-1)
						sessionsWg.Done()
						lock.Lock()
						delete(active, sID)
						lock.Unlock()
						<-sem
					}()
					handleSession(ctx, sID)
				}(id)
			}
		}

		// FIX: backoff extendido si el bucket está rate-limitando
		wait := settings.QueuePollInterval
		if rateLimited {
			wait = settings.QueuePollInterval * 4
			slog.Warn("bucket rate-limitando, backoff extendido", "wait", wait)
		}
		select {
		case <-ctx.Done():
			slog.Info("worker detenido (ctx cancelado)")
			return
		case <-time.After(wait):
		}
	}
}

// heartbeat emite una línea de log periódica para:
//  1. Evitar la cancelación del job por inactividad (10 min en GitHub Actions).
//  2. Dar visibilidad de la carga del relay sin necesidad de métricas externas.
func heartbeat(ctx context.Context) {
	ticker := time.NewTicker(settings.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Info("heartbeat",
				"active_sessions", activeSessions.Load(),
				"gets", store.Gets.Load(),
				"puts", store.Puts.Load(),
				"deletes", store.Deletes.Load(),
				"get_errs", store.GetErrs.Load(),
				"put_errs", store.PutErrs.Load(),
				"rate_hits", store.RateHits.Load(),
			)
		}
	}
}

func main() {
	cfg, err := LoadSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config inválida: %v\n", err)
		os.Exit(1)
	}
	settings = cfg
	initLogger(settings.LogLevel)
	slog.Info("iniciando todus_relay_vps",
		"base_url", settings.BaseURL,
		"encryption", settings.EncryptionEnabled,
		"max_sessions", settings.MaxSessions,
		"allowlist_rules", len(settings.Allowlist),
		"session_max_duration", settings.SessionMaxDuration.String(),
		"shutdown_timeout", settings.ShutdownTimeout.String(),
	)
	store = NewTodusStore(settings)
	allow = ParseAllowlist(settings.Allowlist)

	ctx := SetupSignalContext()

	go heartbeat(ctx)

	worker(ctx)

	// Shutdown graceful: esperar a que las sesiones activas publiquen su
	// estado final (closed/error) o agotar ShutdownTimeout.
	if activeSessions.Load() > 0 {
		slog.Info("esperando sesiones activas en shutdown", "active", activeSessions.Load(), "timeout", settings.ShutdownTimeout.String())
		done := make(chan struct{})
		go func() { sessionsWg.Wait(); close(done) }()
		select {
		case <-done:
			slog.Info("todas las sesiones cerradas graceful")
		case <-time.After(settings.ShutdownTimeout):
			slog.Warn("shutdown timeout, sesiones restantes forzadas", "active", activeSessions.Load())
		}
	}
	slog.Info("relay detenido")
}
