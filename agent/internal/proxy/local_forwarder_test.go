package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalForwarderFormatsIPv6Upstream(t *testing.T) {
	f := NewLocalForwarder("127.0.0.1:0")
	f.SetUpstream("fd7a:115c:a1e0::1", 8888)
	if got := f.Upstream(); got != "[fd7a:115c:a1e0::1]:8888" {
		t.Fatalf("expected bracketed IPv6 upstream, got %q", got)
	}
}

func TestLocalForwarderRejectsNonLoopbackRemote(t *testing.T) {
	f := NewLocalForwarder("127.0.0.1:0")
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "192.0.2.10:4321"
	rec := httptest.NewRecorder()

	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback remote, got %d", rec.Code)
	}
}

func TestLocalForwarderRejectsDirectMode(t *testing.T) {
	f := NewLocalForwarder("127.0.0.1:0")
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()

	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without upstream, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "exit node proxy not configured") {
		t.Fatalf("expected direct-mode rejection message, got %q", rec.Body.String())
	}
}

func TestLocalForwarderRejectsNonConnect(t *testing.T) {
	f := NewLocalForwarder("127.0.0.1:0")
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	rec := httptest.NewRecorder()

	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for non-CONNECT request, got %d", rec.Code)
	}
}
