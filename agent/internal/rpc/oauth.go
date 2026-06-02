package rpc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/auth"
	"github.com/goastian/midorivpn-agent/internal/caps"
	"github.com/goastian/midorivpn-agent/internal/logredact"
)

// oauthCallbackURI is the localhost redirect_uri the agent listens on. The
// concrete URL is now resolved from the layered config
// (cfg.AuthentikRedirectURI). The constant is kept for callers that need a
// stable default (path is fixed by Authentik client registration).
const oauthCallbackURI = "http://127.0.0.1:7071/oauth/callback"

// redirectURI returns the configured redirect URI, falling back to the
// hardcoded default when config is empty (should not happen post-Load).
func (s *Server) redirectURI() string {
	if s.cfg.AuthentikRedirectURI != "" {
		return s.cfg.AuthentikRedirectURI
	}
	return oauthCallbackURI
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func generateRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// pendingOAuthEntry tracks a single in-flight authorization request.
type pendingOAuthEntry struct {
	verifier  string
	expiresAt time.Time
}

// pendingOAuthTTL bounds how long an issued OAuth state remains valid for the
// callback. Authentik's own session is much longer; we only need to cover the
// browser round-trip.
const pendingOAuthTTL = 10 * time.Minute

// maxPendingOAuth bounds the in-memory state map so that a misbehaving or
// malicious client cannot grow it without limit by spamming /oauth/start.
const maxPendingOAuth = 64

// purgePendingOAuthLocked removes expired entries. Caller must hold oauthMu.
func (s *Server) purgePendingOAuthLocked(now time.Time) {
	for state, entry := range s.pendingOAuth {
		if now.After(entry.expiresAt) {
			delete(s.pendingOAuth, state)
		}
	}
}

// handleOAuthStart generates a PKCE pair, stores the state→verifier mapping
// and returns the Authentik authorization URL for the frontend to open in the
// system browser.
//
// POST /oauth/start  →  {"url":"https://accounts.astian.org/..."}
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	verifier, err := generateRandom(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pkce error")
		return
	}
	oauthState, err := generateRandom(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state error")
		return
	}

	now := time.Now()
	s.oauthMu.Lock()
	s.purgePendingOAuthLocked(now)
	if len(s.pendingOAuth) >= maxPendingOAuth {
		s.oauthMu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many pending oauth requests")
		return
	}
	s.pendingOAuth[oauthState] = pendingOAuthEntry{
		verifier:  verifier,
		expiresAt: now.Add(pendingOAuthTTL),
	}
	s.oauthMu.Unlock()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.authentikClientID},
		"redirect_uri":          {s.redirectURI()},
		"scope":                 {"openid email profile offline_access"},
		"state":                 {oauthState},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authURL := strings.TrimRight(s.authentikAuthURL, "/") + "/?" + params.Encode()
	writeJSON(w, map[string]string{"url": authURL})
}

// handleOAuthCallback receives the browser redirect from Authentik, exchanges
// the code for tokens and stores them in the agent state.
//
// GET /oauth/callback?code=...&state=...
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	setLocalSecurityHeaders(w)

	code := r.URL.Query().Get("code")
	oauthState := r.URL.Query().Get("state")

	s.oauthMu.Lock()
	now := time.Now()
	s.purgePendingOAuthLocked(now)
	entry, ok := s.pendingOAuth[oauthState]
	if ok {
		delete(s.pendingOAuth, oauthState)
	}
	s.oauthMu.Unlock()

	if !ok || code == "" || now.After(entry.expiresAt) {
		http.Error(w, "invalid state or missing code", http.StatusBadRequest)
		return
	}
	verifier := entry.verifier

	// Exchange code + PKCE verifier for tokens.
	tokenURL := s.authentikTokenURL
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.redirectURI()},
		"client_id":     {s.authentikClientID},
		"code_verifier": {verifier},
	}
	if s.authentikClientSecret != "" {
		form.Set("client_secret", s.authentikClientSecret)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("oauth: token exchange HTTP error", "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		slog.Warn("oauth: token exchange non-200", "status", resp.StatusCode, "body", logredact.Body(body))
		http.Error(w, fmt.Sprintf("token exchange: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		http.Error(w, "invalid token response", http.StatusInternalServerError)
		return
	}

	// Try to extract username from id_token; fall back to userinfo endpoint.
	username := jwtEmail(tok.IDToken)
	if username == "" && tok.AccessToken != "" {
		username = s.fetchUsername(ctx, tok.AccessToken)
	}

	s.authMgr.Save(auth.Tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		Username:     username,
	})
	slog.Info("oauth: login successful", "user", logredact.User(username))
	go s.refreshServersCache(context.Background())

	// Trigger mesh activation in background unless the user opted out.
	go func() {
		if s.settings != nil && s.settings.Get().Mesh.StartDisabled {
			return
		}
		if !caps.HasNetAdmin() {
			slog.Info("auto-mesh after oauth login: skipped (CAP_NET_ADMIN not granted)")
			return
		}
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer bgCancel()
		if err := s.enableMesh(bgCtx); err != nil {
			slog.Warn("auto-mesh after oauth login failed", "err", err)
		}
	}()

	// Reply with a blank page that immediately closes itself. The desktop app
	// learns of the new auth state through the SSE relay, so the browser tab
	// has no further purpose. If the browser refuses programmatic close
	// (common for tabs the user opened), the page stays visually blank.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body><script>window.close();</script></body></html>`)
}

// jwtEmail extracts email / preferred_username / sub from the id_token payload.
func jwtEmail(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if claims.Email != "" {
		return claims.Email
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	return claims.Sub
}

// fetchUsername calls the OIDC userinfo endpoint to retrieve the user's email
// or preferred_username when the id_token is absent or lacks those claims.
func (s *Server) fetchUsername(ctx context.Context, accessToken string) string {
	userinfoURL := s.authentikUserinfoURL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("oauth: userinfo request failed", "err", err)
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var info struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	if info.Email != "" {
		return info.Email
	}
	if info.PreferredUsername != "" {
		return info.PreferredUsername
	}
	return info.Sub
}
