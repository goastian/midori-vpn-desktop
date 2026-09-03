package apiClient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/config"
)

func TestEnrollDeviceCertificateSendsCSRWithoutPrivateKey(t *testing.T) {
	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/control/certificates" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		requestBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
			"certificate": map[string]any{
				"id": "cert-one", "server_id": "server-one", "device_name": "linux-one",
				"certificate_pem": "CERT", "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-02-01T00:00:00Z",
			},
			"ca_certificate_pem": "CA",
		}})
	}))
	defer server.Close()
	client := New(server.URL, "client", func() string { return "token" }, nil)
	result, err := client.EnrollDeviceCertificate(context.Background(), "server-one", "linux-one", "CSR")
	if err != nil || result.Certificate.ID != "cert-one" {
		t.Fatalf("EnrollDeviceCertificate() = %+v, %v", result, err)
	}
	if !bytes.Contains(requestBody, []byte(`"csr_pem":"CSR"`)) || bytes.Contains(bytes.ToLower(requestBody), []byte("private")) {
		t.Fatalf("unsafe enrollment request body: %s", requestBody)
	}
}

func TestCreateConnectionSendsReportedDeviceName(t *testing.T) {
	var requestBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/control/connections" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]any{
			"peer_id": "peer-one", "peer_ip": "10.8.0.2/32",
		}})
	}))
	defer server.Close()

	client := New(server.URL, "client", func() string { return "token" }, nil)
	result, err := client.CreateConnection(context.Background(), "server-one", "public-key", "Tecno-09", "pq-key")
	if err != nil || result.PeerID != "peer-one" {
		t.Fatalf("CreateConnection() = %+v, %v", result, err)
	}
	if requestBody["device_name"] != "Tecno-09" {
		t.Fatalf("device_name = %q, want reported hostname", requestBody["device_name"])
	}
	if requestBody["server_id"] != "server-one" || requestBody["public_key"] != "public-key" || requestBody["pq_kem_public_key"] != "pq-key" {
		t.Fatalf("unexpected connection request: %#v", requestBody)
	}
}

func TestListDeviceCertificatesPreservesRevocationState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/control/certificates" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": []map[string]any{{
			"id": "cert-one", "server_id": "server-one", "device_name": "linux-one",
			"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-02-01T00:00:00Z",
			"revoked_at": "2026-01-15T00:00:00Z", "revocation_reason": "cessation_of_operation",
		}}})
	}))
	defer server.Close()
	client := New(server.URL, "client", func() string { return "token" }, nil)
	result, err := client.ListDeviceCertificates(context.Background())
	if err != nil || len(result) != 1 || result[0].RevokedAt == nil {
		t.Fatalf("ListDeviceCertificates() = %+v, %v", result, err)
	}
}

func TestOriginFromBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
		wantErr bool
	}{
		{name: "https host", baseURL: "https://vpn.astian.org", want: "https://vpn.astian.org"},
		{name: "explicit port", baseURL: "http://127.0.0.1:8080/api", want: "http://127.0.0.1:8080"},
		{name: "invalid", baseURL: "vpn.astian.org", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := originFromBaseURL(tt.baseURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("originFromBaseURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("originFromBaseURL() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("originFromBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOriginFromConfigAPIURL verifies that the URL coming from config.Load()
// (honours API_URL env var or .env file) is a valid origin for the client.
// Set API_URL in the environment or a .env file to point tests at a custom server.
func TestOriginFromConfigAPIURL(t *testing.T) {
	cfg := config.Load()
	apiURL := cfg.APIURL
	if apiURL == "" {
		t.Skip("API_URL not configured")
	}

	origin, err := originFromBaseURL(apiURL)
	if err != nil {
		t.Fatalf("originFromBaseURL(%q) from config: %v", apiURL, err)
	}
	if origin == "" {
		t.Fatalf("originFromBaseURL(%q) returned empty string", apiURL)
	}
	t.Logf("config API_URL %q -> origin %q", apiURL, origin)
}

// TestClientSendsOriginDerivedFromAPIURL builds a client using the URL from
// config.Load() (respects API_URL env / .env override) and verifies that the
// Origin header on outgoing requests equals the scheme+host of that URL.
// When API_URL is not set the test falls back to the production default.
func TestClientSendsOriginDerivedFromAPIURL(t *testing.T) {
	apiURL := config.Load().APIURL
	if apiURL == "" {
		apiURL = "https://vpn.astian.org"
	}
	// Override so the client actually talks to our test server below.
	os.Setenv("API_URL", "")

	var gotOrigin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"data": []Server{},
		})
	}))
	defer server.Close()

	client := New(server.URL+"/api", "test-client-id", func() string { return "token" }, nil)
	if _, err := client.ListServers(context.Background()); err != nil {
		t.Fatalf("ListServers() error = %v", err)
	}

	if gotOrigin != server.URL {
		t.Fatalf("Origin header = %q, want %q", gotOrigin, server.URL)
	}
}

func TestClientReturnsStructuredAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "code": "origin_country_unavailable", "error": "country lookup unavailable",
		})
	}))
	defer server.Close()

	client := New(server.URL, "test-client-id", func() string { return "token" }, nil)
	_, err := client.ActivateNode(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("ActivateNode() error = %T %v, want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable || apiErr.Code != "origin_country_unavailable" || apiErr.Message != "country lookup unavailable" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
	if !strings.Contains(err.Error(), "[origin_country_unavailable]") {
		t.Fatalf("APIError.Error() = %q, want stable code", err.Error())
	}
	if strings.Contains(err.Error(), apiErr.Message) {
		t.Fatalf("APIError.Error() leaked remote message: %q", err.Error())
	}
}

func TestClientRejectsOversizedCoreResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
	}))
	defer server.Close()

	client := New(server.URL, "test-client-id", func() string { return "token" }, nil)
	_, err := client.ListServers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response_too_large") {
		t.Fatalf("ListServers() error = %v", err)
	}
}

func TestClientRejectsUnsafeRemoteErrorCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"code":"INVALID CODE","error":"provider-secret"}`))
	}))
	defer server.Close()

	client := New(server.URL, "test-client-id", func() string { return "token" }, nil)
	_, err := client.ActivateNode(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "" {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("APIError.Error() leaked remote message: %q", err.Error())
	}
}
