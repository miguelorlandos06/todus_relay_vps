package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Errores tipados para que el worker pueda reaccionar de forma distinta
// a "ausente" (normal en polling) frente a "rate limit" o "forbidden".
var (
	ErrAbsent      = errors.New("objeto ausente")
	ErrForbidden   = errors.New("acceso denegado")
	ErrRateLimited = errors.New("rate limit")
)

type StoreStatus int

const (
	StatusFound StoreStatus = iota
	StatusAbsent
	StatusForbidden
	StatusRateLimited
	StatusNetworkError
)

func (s StoreStatus) String() string {
	switch s {
	case StatusFound:
		return "found"
	case StatusAbsent:
		return "absent"
	case StatusForbidden:
		return "forbidden"
	case StatusRateLimited:
		return "rate_limited"
	case StatusNetworkError:
		return "network_error"
	}
	return "unknown"
}

type TodusStore struct {
	settings *Settings
	client   *http.Client
	aesKey   []byte

	// Métricas atómicas para el heartbeat
	Gets     atomic.Int64
	Puts     atomic.Int64
	Deletes  atomic.Int64
	GetErrs  atomic.Int64
	PutErrs  atomic.Int64
	RateHits atomic.Int64
}

func NewTodusStore(settings *Settings) *TodusStore {
	tr := &http.Transport{
		// v2.0: pool ampliado (256 por host) para sostener 14 sesiones con
		// prefetch sin cerrar conexiones: el handshake TLS es lo más caro.
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		MaxConnsPerHost:     256,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !settings.VerifyTLS},
	}
	var aesKey []byte
	if settings.EncryptionEnabled {
		aesKey = deriveAESKey(settings.SharedSecret)
	}
	return &TodusStore{
		settings: settings,
		client:   &http.Client{Transport: tr, Timeout: settings.HTTPTimeout},
		aesKey:   aesKey,
	}
}

func (s *TodusStore) buildURL(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return fmt.Sprintf("%s/%s", s.settings.BaseURL, strings.Join(parts, "/"))
}

// seal envuelve data en un sobre autenticado.
//   - Si EncryptionEnabled=true: TDS3 (magic + HMAC + nonce + ciphertext AES-GCM)
//   - Si no: TDS2 legacy (magic + HMAC + plaintext)
//
// El HMAC cubre key || 0x00 || blob para vincular el objeto a su llave
// y prevenir ataques de relocalización de objetos entre llaves.
func (s *TodusStore) seal(key string, data []byte) []byte {
	var blob []byte
	magic := EnvelopeMagicLegacy
	if s.settings.EncryptionEnabled && s.aesKey != nil {
		enc, err := encryptAESGCM(s.aesKey, data)
		if err != nil {
			slog.Error("encrypt falló, degradando a legacy", "err", err)
			blob = data
		} else {
			blob = enc
			magic = EnvelopeMagicSecure
		}
	} else {
		blob = data
	}

	h := hmac.New(sha256.New, s.settings.SharedSecret)
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write(blob)
	tag := h.Sum(nil)

	out := make([]byte, 4+TagSize+len(blob))
	copy(out[0:4], magic)
	copy(out[4:4+TagSize], tag)
	copy(out[4+TagSize:], blob)
	return out
}

// open verifica y devuelve data. Soporta TDS2 (legacy) y TDS3 (cifrado).
// Devuelve nil si el sobre es inválido (HMAC incorrecto, magic desconocido,
// o decrypt falló).
func (s *TodusStore) open(key string, envelope []byte) []byte {
	if len(envelope) < 4+TagSize {
		return nil
	}
	magic := envelope[:4]
	isLegacy := bytes.Equal(magic, EnvelopeMagicLegacy)
	isSecure := bytes.Equal(magic, EnvelopeMagicSecure)
	if !isLegacy && !isSecure {
		return nil
	}
	tag := envelope[4 : 4+TagSize]
	blob := envelope[4+TagSize:]

	h := hmac.New(sha256.New, s.settings.SharedSecret)
	h.Write([]byte(key))
	h.Write([]byte{0})
	h.Write(blob)
	if !hmac.Equal(tag, h.Sum(nil)) {
		slog.Warn("HMAC inválido en objeto", "key", key)
		return nil
	}

	if isSecure {
		if s.aesKey == nil {
			slog.Warn("objeto TDS3 recibido pero cifrado deshabilitado", "key", key)
			return nil
		}
		plain, err := decryptAESGCM(s.aesKey, blob)
		if err != nil {
			slog.Warn("decrypt falló", "key", key, "err", err)
			return nil
		}
		return plain
	}
	// TDS2 legacy: blob es plaintext ya autenticado
	return blob
}

// newRequest crea la petición base con UA y Host opcionales (v2.0).
func (s *TodusStore) newRequest(method, targetURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.userAgent())
	if s.settings.HostHeader != "" {
		req.Host = s.settings.HostHeader
	}
	return req, nil
}

// userAgent permite sobrescribir el UA vía USER_AGENT (para no depender
// siempre del curl por defecto y reducir fingerprinting).
func (s *TodusStore) userAgent() string {
	if ua := strings.TrimSpace(os.Getenv("USER_AGENT")); ua != "" {
		return ua
	}
	return "curl/8.23.0"
}

// maxBodySize acota la lectura de respuestas (64 MiB) para no desbordar la
// memoria ante respuestas anómalas del bucket.
const maxBodySize = 64 << 20

// readBody lee y cierra el cuerpo acotado a maxBodySize.
func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
}

// Get mantiene la firma original ([]byte) para los bucles de polling
// existentes: devuelve nil para ausente/forbidden/ratelimited, con
// log interno para los casos no-absentes.
func (s *TodusStore) Get(key string, retries int) []byte {
	data, status := s.GetWithStatus(key, retries)
	if status == StatusForbidden || status == StatusNetworkError {
		slog.Debug("get no encontrado", "key", key, "status", status.String())
	}
	return data
}

// GetWithStatus retorna data y un status tipado, para que el worker
// pueda backoffear selectivamente ante rate limit.
func (s *TodusStore) GetWithStatus(key string, retries int) ([]byte, StoreStatus) {
	targetURL := s.buildURL(key)
	var lastStatus StoreStatus
	for attempt := 0; attempt <= retries; attempt++ {
		s.Gets.Add(1)
		req, err := s.newRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			lastStatus = StatusNetworkError
			continue
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastStatus = StatusNetworkError
			s.GetErrs.Add(1)
			backoff := time.Duration(50*(attempt+1)) * time.Millisecond
			slog.Debug("get error red", "key", key, "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		body, _ := readBody(resp)
		switch {
		case resp.StatusCode == http.StatusOK:
			return s.open(key, body), StatusFound
		case resp.StatusCode == http.StatusNotFound:
			return nil, StatusAbsent
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
			s.GetErrs.Add(1)
			slog.Warn("get auth error", "key", key, "status", resp.StatusCode)
			return nil, StatusForbidden
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			s.RateHits.Add(1)
			lastStatus = StatusRateLimited
			backoff := time.Duration(200*(attempt+1)) * time.Millisecond
			slog.Warn("get rate limit / 5xx", "key", key, "status", resp.StatusCode, "backoff", backoff)
			time.Sleep(backoff)
			continue
		default:
			lastStatus = StatusNetworkError
			slog.Warn("get status inesperado", "key", key, "status", resp.StatusCode)
		}
	}
	return nil, lastStatus
}

func (s *TodusStore) Put(key string, data []byte) bool {
	targetURL := s.buildURL(key)
	sealed := s.seal(key, data)
	for attempt := 0; attempt <= s.settings.HTTPRetries; attempt++ {
		s.Puts.Add(1)
		req, err := s.newRequest(http.MethodPut, targetURL, bytes.NewReader(sealed))
		if err != nil {
			continue
		}
		resp, err := s.client.Do(req)
		if err != nil {
			s.PutErrs.Add(1)
			backoff := time.Duration(100*(attempt+1)) * time.Millisecond
			slog.Debug("put error red", "key", key, "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			s.RateHits.Add(1)
			backoff := time.Duration(200*(attempt+1)) * time.Millisecond
			slog.Warn("put rate limit / 5xx", "key", key, "status", resp.StatusCode, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		s.PutErrs.Add(1)
		// FIX: ya no se ignora el fallo; se registra para diagnóstico
		slog.Warn("put falló", "key", key, "status", resp.StatusCode)
		return false
	}
	slog.Error("put agotó reintentos", "key", key)
	return false
}

func (s *TodusStore) Delete(key string) bool {
	targetURL := s.buildURL(key)
	req, err := s.newRequest(http.MethodDelete, targetURL, nil)
	if err != nil {
		return false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		slog.Debug("delete error red", "key", key, "err", err)
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	s.Deletes.Add(1)
	return resp.StatusCode == 200 || resp.StatusCode == 202 || resp.StatusCode == 204 || resp.StatusCode == 404
}
