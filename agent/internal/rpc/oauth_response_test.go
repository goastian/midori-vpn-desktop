package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteOAuthSuccessRedirectsBrowserInTheSameTab(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7071/oauth/callback", nil)
	recorder := httptest.NewRecorder()

	writeOAuthSuccess(recorder, req, "user@example.test")

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if location := recorder.Header().Get("Location"); location != "/" {
		t.Fatalf("Location = %q, want /", location)
	}
}

func TestWriteOAuthSuccessKeepsJSONClientsOnTheCallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7071/oauth/callback", nil)
	req.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()

	writeOAuthSuccess(recorder, req, "user@example.test")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Header().Get("Location") != "" {
		t.Fatal("JSON callback must not redirect")
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["ok"] != true || payload["username"] != "user@example.test" {
		t.Fatalf("response = %#v", payload)
	}
}
