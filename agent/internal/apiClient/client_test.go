package apiClient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestClientSendsOriginDerivedFromBaseURL(t *testing.T) {
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

	client := New(server.URL+"/api", func() string { return "token" }, nil)
	if _, err := client.ListServers(context.Background()); err != nil {
		t.Fatalf("ListServers() error = %v", err)
	}

	if gotOrigin != server.URL {
		t.Fatalf("Origin = %q, want %q", gotOrigin, server.URL)
	}
}
