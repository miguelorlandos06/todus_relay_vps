package main

import (
	"log/slog"
	"strconv"
	"strings"
)

// Allowlist filtra destinos (host:port) para evitar que el relay se
// convierta en un open proxy si el secreto compartido se filtra.
//
// Formato de reglas (separadas por coma en ALLOWLIST):
//
//	host:port     host exacto, puerto exacto
//	host:*        host exacto, cualquier puerto
//	*.domain:port cualquier subdominio de domain, puerto exacto
//	*.domain:*    cualquier subdominio, cualquier puerto
//
// Si la lista está vacía se permite todo (backward compat) con un warning.
type Allowlist struct {
	rules []allowRule
}

type allowRule struct {
	host     string // host exacto o sufijo (si wildcard)
	wildcard bool   // true si la regla era *.domain
	port     int    // 0 = cualquier puerto
}

func ParseAllowlist(patterns []string) *Allowlist {
	a := &Allowlist{}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		host, portStr, ok := strings.Cut(p, ":")
		if !ok {
			slog.Warn("allowlist: regla sin puerto, ignorada", "rule", p)
			continue
		}
		host = strings.TrimSpace(host)
		portStr = strings.TrimSpace(portStr)
		r := allowRule{}
		if strings.HasPrefix(host, "*.") {
			r.wildcard = true
			r.host = strings.TrimPrefix(host, "*.")
		} else {
			r.host = host
		}
		if portStr != "*" {
			r.port, _ = strconv.Atoi(portStr)
		}
		a.rules = append(a.rules, r)
	}
	if len(a.rules) > 0 {
		slog.Info("allowlist parseado", "rules", len(a.rules))
	}
	return a
}

// Allow decide si un destino está permitido.
func (a *Allowlist) Allow(host string, port int) bool {
	if a == nil || len(a.rules) == 0 {
		return true
	}
	host = strings.TrimSpace(host)
	for _, r := range a.rules {
		if r.port != 0 && r.port != port {
			continue
		}
		if r.wildcard {
			if host == r.host || strings.HasSuffix(host, "."+r.host) {
				return true
			}
		} else if r.host == host {
			return true
		}
	}
	return false
}
