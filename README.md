# todus_relay_vps

Relay de túnel TCP/UDP sobre almacenamiento S3, escrito en Go 1.22 usando **solo la biblioteca estándar** (sin dependencias externas). Pensado para ejecutarse en GitHub Actions como punto de salida (egress).

> **Versión mejorada.** Esta versión corrige los bugs del original (if vacío en `main.go:150`, fuga de memoria del mapa `seen`, errores de write ignorados, etc.) y añade: cifrado AES-GCM del payload, allowlist de destinos, SIGTERM graceful, logging estructurado (`log/slog`), heartbeat, distinción 404/403/429 en S3, y un workflow de GitHub Actions con schedule cron y shutdown limpio.

> **Versión 2.0.** Sincronizada con la APK ToDus Relay VPN 2.0.0:
> - **Bucket nuevo**: `TODUS_BASE_URL=https://s3.todus.cu/public`.
> - **Defaults sincronizados con la APK**: poll 0.5 s, chunk 1 MiB, ventana 24, ACK cada 6, sesiones 14, UDP 64/50 ms/128 KiB/160 flujos/poll 60 ms/6 workers.
> - **Prefetch c2s con pipeline** (`framePrefetcher`): el GET del bloque N+1 se solapa con la escritura del N (hasta 8 bloques por delante); la latencia del sondeo deja de limitar el caudal de descarga.
> - **Sondeo adaptativo de ACK** en `waitForWindow`: mientras la ventana no avanza, el intervalo crece hasta 4× para no saturar el bucket con GETs inútiles.
> - **Chequeo de cierre espaciado** (500 ms) en TCP y UDP: elimina un GET extra por sondeo/frame.
> - **Pool HTTP ampliado** (256 conexiones por host, keep-alive 120 s) y lectura de cuerpos acotada (`io.LimitReader`, 64 MiB).
> - **TCP_NODELAY** explícito en los destinos y **jitter ±20 %** en el sondeo de la cola.
> - `TODUS_HOST_HEADER` opcional (paridad con la APK, que envía `Host: status.todus.cu`).

## Arquitectura

```
Cliente ──(HTTP PUT/GET/DELETE anónimo)──> Bucket S3 (s3.todus.cu/public)
                                              ▲
                                              │ sondeo (poll)
                                              │
                                          Relay (este binario)
                                              │
                                              ▼ net.Dial TCP/UDP
                                         Destino final
```

- **Transporte encubierto**: todo se ve como peticiones S3 anónimas con `User-Agent: curl/8.23.0` (configurable vía `USER_AGENT`).
- **Protocolo**: frames `TDV2` (TCP), lotes `TDU2` (UDP), sobres `TDS2` (legacy HMAC) y `TDS3` (HMAC + AES-GCM cifrado).
- **Store-and-forward**: no hay conexión directa cliente↔relay; la coordinación es por convención de llaves `_v2_*` en el bucket.

## Ficheros

| Fichero | Función |
| --- | --- |
| `main.go` | Worker, manejo de sesión TCP/UDP, shutdown graceful, heartbeat |
| `config.go` | `Settings`, carga desde `.env` / variables de entorno |
| `protocol.go` | Frames `TDV2`, lotes `TDU2`, helpers de llaves |
| `store.go` | Cliente HTTP S3, sobres `TDS2`/`TDS3`, backoff, métricas |
| `crypto.go` | Derivación de clave AES-256 y cifrado AES-GCM |
| `allowlist.go` | Filtro de destinos (anti open-proxy) |
| `logger.go` | `log/slog` JSON a stdout |
| `shutdown.go` | Captura SIGTERM/SIGINT → context cancel |

## Configuración

Copia `.env.example` a `.env` y rellena los valores, o define las variables de entorno directamente. Las variables críticas:

| Variable | Default | Descripción |
| --- | --- | --- |
| `PROXY_SHARED_SECRET` | (obligatorio) | Secreto HMAC + AES en hex, mínimo 32 bytes. `openssl rand -hex 32` |
| `TODUS_BASE_URL` | `https://s3.todus.cu/public` | URL del bucket |
| `ENCRYPTION_ENABLED` | `true` | Cifrado AES-GCM del payload (sobre `TDS3`). `false` = `TDS2` legacy |
| `ALLOWLIST` | (vacío) | Reglas `host:port` separadas por coma. Vacío = permitir todo (con warning) |
| `HEARTBEAT_INTERVAL` | `60` | Segundos entre logs de heartbeat (evita cancelación por inactividad en GH Actions) |
| `SESSION_MAX_DURATION` | `14400` (4h) | Duración máxima por sesión (< límite 6h del job) |
| `SHUTDOWN_TIMEOUT` | `20` | Segundos de gracia tras SIGTERM |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `WRITE_TIMEOUT` | `15` | Timeout de escritura al destino TCP (separado de `CONNECT_TIMEOUT`) |

Ver `.env.example` para el resto de tuning (chunk size, window, UDP, etc.).

## Desarrollo local

```bash
make vet          # go vet
make test         # go test
make race         # go test -race
make build        # genera ./todus_relay_vps
./todus_relay_vps # corre con .env en CWD
```

Requisitos: Go 1.22+.

## Despliegue en GitHub Actions

El repo incluye dos workflows:

- `.github/workflows/ci.yml` — CI: `go vet`, `go test -race`, build en cada push/PR.
- `.github/workflows/relay.yml` — Ejecuta el relay en schedule cron cada 5h 30min (deja margen antes del límite de 6h/job). Captura SIGTERM para shutdown graceful.

### Pasos para desplegar

1. **Crea los secrets del repo** (Settings → Secrets and variables → Actions → New repository secret):
   - `PROXY_SHARED_SECRET` — genera con `openssl rand -hex 32`
   - `ALLOWLIST` (recomendado) — ej. `1.1.1.1:53,*.mi-dominio.com:443`
2. **(Opcional) Crea variables del repo** para el resto de config no sensible:
   - `TODUS_BASE_URL`, `MAX_SESSIONS`, `LOG_LEVEL`, etc.
3. **Programa el workflow**: edita `.github/workflows/relay.yml` y ajusta el `cron` a tu zona horaria y cadencia. Por defecto cada 30 minutos pasado cada 5h (`0 */5 * * *` estilo, ver fichero).
4. **Lanza manualmente** la primera vez desde la pestaña Actions → "Run workflow" para verificar.
5. **Monitoriza**: abre el job en curso y observa los logs JSON. El heartbeat imprime `active_sessions`, `gets`, `puts`, `rate_hits` cada 60s.

### Notas operativas

- **Límite 6h/job**: GitHub mata el job a las 6h. El schedule deja margen (5h30min) para que el proceso haga shutdown graceful.
- **IP de egress variable**: cada runner tiene IP distinta. Si tus destinos filtran por IP, considera añadir un proxy de salida estable.
- **Cancelación por inactividad**: si el job no imprime logs durante 10 min, GitHub puede cancelarlo. El `heartbeat` (60s por defecto) lo evita.
- **Términos de servicio**: revisa los [GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies). Considera runners self-hosted o un VPS si la carga es alta o el uso es delicado.
- **Coste**: Actions consume minutos facturables en repos privados. El job de 6h cada ~5h30min ≈ ~26 runs/día ≈ ~150h/día. En repos públicos es gratis.

## Modelo de seguridad

- **Autenticación**: HMAC-SHA256 con clave de 32+ bytes, comparación de tiempo constante (`hmac.Equal`), binding de la llave al MAC (anti relocalización).
- **Cifrado**: AES-256-GCM con clave derivada del secreto vía HMAC-SHA256 (`deriveAESKey`). El payload es ilegible sin el secreto, incluso con acceso de lectura al bucket.
- **Allowlist**: si se configura, solo los destinos listados son aceptados; el resto se rechaza con `status=error`. Evita open-proxy si el secreto se filtra.
- **TLS**: verificado por defecto (`InsecureSkipVerify` solo si `TODUS_VERIFY_TLS=false`).

## Compatibilidad con clientes legacy

Si `ENCRYPTION_ENABLED=true` (default), el relay **escribe** sobres `TDS3` (cifrados) pero **lee** tanto `TDS2` (legacy, plaintext) como `TDS3`. Esto permite migrar clientes gradualmente: un cliente antiguo que siga escribiendo `TDS2` seguirá siendo leído por el relay nuevo. Un cliente nuevo que lea del bucket debe soportar `TDS3` (descifrar con el mismo secreto).

Para forzar escritura legacy (compatibilidad total con clientes antiguos), pon `ENCRYPTION_ENABLED=false`.

## Licencia

Código del usuario. Ver repositorio original.
