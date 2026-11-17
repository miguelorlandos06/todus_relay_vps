package main

import "testing"

func TestAllowlistEmptyAllowsAll(t *testing.T) {
	a := ParseAllowlist(nil)
	if !a.Allow("anything.example", 9999) {
		t.Fatal("allowlist vacío debe permitir todo")
	}
}

func TestAllowlistExactHostPort(t *testing.T) {
	a := ParseAllowlist([]string{"1.2.3.4:443", "api.example.com:80"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"1.2.3.4", 443, true},
		{"1.2.3.4", 80, false},  // puerto no permitido
		{"1.2.3.5", 443, false}, // host no permitido
		{"api.example.com", 80, true},
		{"api.example.com", 443, false},
		{"other.example.com", 80, false},
	}
	for _, c := range cases {
		if got := a.Allow(c.host, c.port); got != c.want {
			t.Fatalf("Allow(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestAllowlistWildcardAndStarPort(t *testing.T) {
	a := ParseAllowlist([]string{"*.example.com:*", "10.0.0.0:53"})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"api.example.com", 443, true},
		{"sub.api.example.com", 8080, true},
		{"example.com", 80, true}, // host == suffix base
		{"notexample.com", 80, false},
		{"10.0.0.0", 53, true},
		{"10.0.0.1", 53, false},
	}
	for _, c := range cases {
		if got := a.Allow(c.host, c.port); got != c.want {
			t.Fatalf("Allow(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestParseAllowlistIgnoresBadRules(t *testing.T) {
	a := ParseAllowlist([]string{"", "  ", "no-port", "good.host:443"})
	if len(a.rules) != 1 {
		t.Fatalf("esperaba 1 regla válida, got %d", len(a.rules))
	}
}
