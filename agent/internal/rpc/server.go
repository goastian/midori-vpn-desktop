// Package rpc implements the local HTTP API server that the Tauri shell and
// Vue UI use to communicate with the Go agent. It also serves an SSE stream
// for real-time state updates.
package rpc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/auth"
	"github.com/goastian/midorivpn-agent/internal/config"
	"github.com/goastian/midorivpn-agent/internal/firewall"
	"github.com/goastian/midorivpn-agent/internal/mesh"
	"github.com/goastian/midorivpn-agent/internal/netguard"
	"github.com/goastian/midorivpn-agent/internal/proxy"
	"github.com/goastian/midorivpn-agent/internal/settings"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/sysstate"
	"github.com/goastian/midorivpn-agent/internal/wg"
)

// localFwdPort is the localhost-only HTTP CONNECT proxy port that chains to
// an exit node. Applications can set http_proxy=http://127.0.0.1:8889 to
// route their traffic through the mesh exit node.
const localFwdPort = 8889

// Server is the local RPC HTTP server.
type Server struct {
	agent     *state.Agent
	port      int
	wgMgr     *wg.Manager
	guard     *netguard.Guard
	proxySrv  *proxy.Server
	socks5Srv *proxy.SOCKS5Server
	proxyCtx  context.CancelFunc
	localFwd  *proxy.LocalForwarder
	apiClient *apiClient.Client

	// Resolved runtime configuration (defaults + dotenv overrides + env).
	cfg config.Config

	// Persistent OAuth token manager (Secret Service / encrypted file +
	// proactive refresh). Replaces the previous in-memory pendingOAuth +
	// state.AuthStatus storage.
	authMgr *auth.Manager

	// User-controlled preferences (mesh.start_disabled, autostart, …).
	settings *settings.Store

	// Configurable from env / Tauri startup args.
	apiURL  string
	jwksURL string

	// OAuth / PKCE state store.
	oauthMu               sync.Mutex
	pendingOAuth          map[string]string // state → PKCE verifier
	authentikIssuer       string
	authentikClientID     string
	authentikClientSecret string
	authentikAuthURL      string
	authentikTokenURL     string
	authentikUserinfoURL  string

	serversMu            sync.Mutex
	serversCache         []apiClient.Server
	serversCacheAt       time.Time
	serversRefreshActive bool

	vpnStatsMu     sync.Mutex
	vpnStatsCancel context.CancelFunc

	// Connect serialization: last request wins.
	// connectMu guards connectCancel and connectSeq. A new connect call
	// cancels the in-progress one and takes ownership via monotonic connectSeq.
	connectMu     sync.Mutex
	connectCancel context.CancelFunc
	connectSeq    uint64
}

// NewServer creates the RPC server. Configuration is loaded from layered
// sources (defaults → /etc/midorivpn/config.env → user config → env vars).
func NewServer(ag *state.Agent, port int) *Server {
	cfg := config.Load()

	settingsStore, err := settings.New()
	if err != nil {
		slog.Warn("settings store unavailable; defaults will be used", "err", err)
	}

	s := &Server{
		agent:    ag,
		port:     port,
		wgMgr:    wg.NewManager(),
		guard:    netguard.New(),
		localFwd: proxy.NewLocalForwarder(fmt.Sprintf("127.0.0.1:%d", localFwdPort)),
		cfg:      cfg,
		settings: settingsStore,
		apiURL:   cfg.APIURL,
		jwksURL:  cfg.AuthentikJWKSURL,

		pendingOAuth:          make(map[string]string),
		authentikIssuer:       cfg.AuthentikIssuer,
		authentikClientID:     cfg.AuthentikClientID,
		authentikClientSecret: cfg.AuthentikClientSecret,
		authentikAuthURL:      cfg.AuthentikAuthURL,
		authentikTokenURL:     cfg.AuthentikTokenURL,
		authentikUserinfoURL:  cfg.AuthentikUserinfoURL,
	}

	// Build the auth manager BEFORE the apiClient so the apiClient's refresh
	// callback can delegate into the manager's coalesced refresh.
	store := auth.NewStore()
	refreshFn := func(ctx context.Context, refreshToken string) (string, string, int64, error) {
		if s.apiClient == nil {
			return "", "", 0, fmt.Errorf("apiClient not initialised")
		}
		ac, rt, expIn, rerr := s.apiClient.RefreshToken(ctx, refreshToken)
		if rerr != nil {
			msg := rerr.Error()
			if strings.Contains(msg, "api error 400") || strings.Contains(msg, "api error 401") {
				return "", "", 0, &auth.DefiniteAuthError{Err: rerr}
			}
			return "", "", 0, rerr
		}
		return ac, rt, int64(expIn), nil
	}
	notifier := func(t auth.Tokens, loggedIn bool) {
		if !loggedIn {
			ag.SetAuth(state.AuthStatus{})
			return
		}
		ag.SetAuth(state.AuthStatus{
			LoggedIn:     true,
			Username:     t.Username,
			AccessToken:  t.AccessToken,
			RefreshToken: t.RefreshToken,
			ExpiresAt:    t.ExpiresAt,
		})
	}
	s.authMgr = auth.NewManager(store, refreshFn, notifier)

	s.apiClient = apiClient.New(s.apiURL, ag.GetAccessToken, func(ctx context.Context) error {
		// Use SoftRefreshNow so that a 401 returned by any regular API call
		// (e.g. CreateConnection) triggers a token refresh attempt WITHOUT
		// clearing the session.  Only the manager's own scheduled proactive
		// refresh (RefreshNow) is allowed to clear tokens on definitive failure.
		_, err := s.authMgr.SoftRefreshNow(ctx)
		return err
	})
	s.loadServersCacheFromDisk()
	return s
}

// Init performs startup work that needs a context (loading persisted tokens,
// initial refresh if expired). Call once before Start.
func (s *Server) Init(ctx context.Context) error {
	return s.authMgr.Init(ctx)
}

// AutoEnableMesh runs in the background after startup. It waits up to
// ~30 seconds for valid auth tokens to be available, honours the user's
// `mesh.start_disabled` preference, and enables the mesh node with simple
// exponential backoff on transient errors.
//
// On a fresh install with no stored tokens this returns quickly without
// doing anything — the OAuth callback will trigger mesh enable after login.
func (s *Server) AutoEnableMesh(ctx context.Context) {
	if s.settings != nil && s.settings.Get().Mesh.StartDisabled {
		slog.Info("auto-mesh: skipped (user opted out)")
		return
	}

	// Wait for auth to be ready (in case Init is still running an initial
	// refresh).
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for !s.authMgr.LoggedIn() {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			slog.Info("auto-mesh: no auth after 30s; deferring to UI login")
			return
		case <-tick.C:
		}
	}

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		// Recheck the user setting on each attempt so a quick toggle off
		// during a slow first attempt aborts cleanly.
		if s.settings != nil && s.settings.Get().Mesh.StartDisabled {
			slog.Info("auto-mesh: aborted (user opted out mid-retry)")
			return
		}
		callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := s.enableMesh(callCtx)
		cancel()
		if err == nil {
			slog.Info("auto-mesh: enabled", "attempts", attempt)
			return
		}
		// On a permanent auth error, stop retrying. The user will need to
		// re-login; the OAuth callback will retry on success.
		if !s.authMgr.LoggedIn() {
			slog.Info("auto-mesh: aborting (no longer authenticated)")
			return
		}
		slog.Warn("auto-mesh: enable failed; will retry", "attempt", attempt, "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// Start begins serving. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Read the ephemeral token injected by Tauri via env var.
	// If the token is empty (agent launched outside Tauri, e.g. manual debug),
	// log a warning and proceed without token enforcement so developers are not
	// blocked. In production the token is always set.
	agentToken := os.Getenv("MIDORIVPN_AGENT_TOKEN")
	if agentToken == "" {
		slog.Warn("MIDORIVPN_AGENT_TOKEN is not set; token enforcement disabled")
	}

	// allowedOrigin is baked at compile time via -ldflags.
	allowedOrigin := config.AllowedOrigin

	// withCORS sets CORS headers and enforces the allowed origin.
	withCORS := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Agent-Token")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	// requireAuth enforces Origin and token on every non-OPTIONS request.
	// SSE (GET /events) accepts the token via ?token= query param because
	// EventSource does not support custom headers.
	// The OAuth callback (/oauth/callback) is exempt: it is reached by the
	// system browser which cannot set our Origin or token headers.
	requireAuth := func(h http.Handler, allowQueryToken bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				h.ServeHTTP(w, r)
				return
			}

			// Loopback check — reject anything not from 127.0.0.1.
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil || (host != "127.0.0.1" && host != "::1") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			// Origin check.
			origin := r.Header.Get("Origin")
			if origin != "" && origin != allowedOrigin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			// Token check (skip if token enforcement is disabled in dev mode).
			if agentToken != "" {
				var incoming string
				if allowQueryToken {
					incoming = r.URL.Query().Get("token")
				}
				if incoming == "" {
					incoming = r.Header.Get("X-Agent-Token")
				}
				if subtle.ConstantTimeCompare([]byte(incoming), []byte(agentToken)) != 1 {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}

			h.ServeHTTP(w, r)
		})
	}

	wrap := func(h http.Handler) http.Handler {
		return requireAuth(withCORS(h), false)
	}
	wrapSSE := func(h http.Handler) http.Handler {
		return requireAuth(withCORS(h), true)
	}

	mux.Handle("GET /status", wrap(http.HandlerFunc(s.handleStatus)))
	mux.Handle("GET /events", wrapSSE(http.HandlerFunc(s.handleSSE)))

	mux.Handle("POST /auth/set-tokens", wrap(http.HandlerFunc(s.handleSetTokens)))
	mux.Handle("DELETE /auth/logout", wrap(http.HandlerFunc(s.handleLogout)))
	mux.Handle("POST /auth/refresh", wrap(http.HandlerFunc(s.handleRefreshToken)))

	mux.Handle("GET /servers", wrap(http.HandlerFunc(s.handleListServers)))
	mux.Handle("GET /connections", wrap(http.HandlerFunc(s.handleListConnections)))
	mux.Handle("DELETE /connections/{id}", wrap(http.HandlerFunc(s.handleDeleteConnection)))

	mux.Handle("POST /vpn/connect", wrap(http.HandlerFunc(s.handleVPNConnect)))
	mux.Handle("POST /vpn/disconnect", wrap(http.HandlerFunc(s.handleVPNDisconnect)))

	mux.Handle("POST /mesh/enable", wrap(http.HandlerFunc(s.handleMeshEnable)))
	mux.Handle("POST /mesh/disable", wrap(http.HandlerFunc(s.handleMeshDisable)))

	// User preferences (mesh.start_disabled, autostart, …).
	mux.Handle("GET /settings", wrap(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("PUT /settings", wrap(http.HandlerFunc(s.handlePutSettings)))
	// POST alias so callers using the Tauri agent_post helper (which only
	// emits POST) can still update settings without a dedicated agent_put
	// Tauri command.
	mux.Handle("POST /settings", wrap(http.HandlerFunc(s.handlePutSettings)))
	mux.Handle("GET /mesh/exit-nodes", wrap(http.HandlerFunc(s.handleListExitNodes)))
	mux.Handle("POST /mesh/exit-node", wrap(http.HandlerFunc(s.handleSetExitNode)))
	mux.Handle("DELETE /mesh/exit-node", wrap(http.HandlerFunc(s.handleClearExitNode)))
	mux.Handle("POST /mesh/full-tunnel/enable", wrap(http.HandlerFunc(s.handleMeshFullTunnelEnable)))
	mux.Handle("POST /mesh/full-tunnel/disable", wrap(http.HandlerFunc(s.handleMeshFullTunnelDisable)))

	// Utility: check current public IP (routes through WireGuard tunnel if connected).
	mux.Handle("GET /public-ip", wrap(http.HandlerFunc(s.handlePublicIP)))

	// OAuth 2.0 PKCE login flow.
	// /oauth/start is called from Tauri (has token); /oauth/callback is reached
	// by the system browser (exempt from token+Origin check).
	mux.Handle("POST /oauth/start", wrap(http.HandlerFunc(s.handleOAuthStart)))
	mux.Handle("GET /oauth/callback", http.HandlerFunc(s.handleOAuthCallback))

	// Start the local transparent forwarder (chains to exit node when active).
	go func() {
		if err := s.localFwd.Start(ctx); err != nil {
			slog.Error("local forwarder error", "err", err)
		}
	}()

	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		// Best-effort clean shutdown so we leave no zombie wg0 device or
		// stale mesh registration on the backend.
		s.gracefulShutdown()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	slog.Info("agent RPC listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ----- status -----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.agent.Snapshot()
	// Augment with local proxy info so the UI can guide users.
	snap["local_proxy"] = map[string]any{
		"port":     localFwdPort,
		"active":   s.localFwd.Active(),
		"upstream": s.localFwd.Upstream(),
		"hint":     fmt.Sprintf("Set http_proxy=http://127.0.0.1:%d to route browser/app traffic through the exit node", localFwdPort),
	}
	snap["kill_switch"] = map[string]any{
		"active": s.guard.Active(),
	}
	snap["dns_protected"] = s.wgMgr.DNSProtected()
	writeJSON(w, snap)
}

// ----- SSE -----

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "tauri://localhost")

	// Send initial snapshot.
	data, _ := json.Marshal(s.agent.Snapshot())
	fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
	flusher.Flush()

	ch, cancel := s.agent.Subscribe()
	defer cancel()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			data, _ := json.Marshal(s.agent.Snapshot())
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			flusher.Flush()
		case <-time.After(30 * time.Second):
			// Heartbeat to keep connection alive.
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// ----- auth -----

func (s *Server) handleSetTokens(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
		Username     string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ExpiresAt == 0 && req.ExpiresIn > 0 {
		req.ExpiresAt = time.Now().Add(time.Duration(req.ExpiresIn) * time.Second).Unix()
	}

	if err := s.authMgr.Save(auth.Tokens{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		ExpiresAt:    req.ExpiresAt,
		Username:     req.Username,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go s.refreshServersCache(context.Background())

	// Auto-activate mesh on login (best-effort, non-blocking) unless the
	// user has explicitly disabled mesh-at-startup.
	go func() {
		if s.settings != nil && s.settings.Get().Mesh.StartDisabled {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.enableMesh(ctx); err != nil {
			slog.Warn("auto-mesh on login failed", "err", err)
		}
	}()

	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.stopVPNStatsLoop()

	// Cancel any in-progress VPN connect so it cannot race with cleanup.
	s.connectMu.Lock()
	if s.connectCancel != nil {
		s.connectCancel()
		s.connectCancel = nil
	}
	s.connectSeq++ // invalidate any superseded connect that beat the cancel
	s.connectMu.Unlock()

	// Disconnect VPN if connected.
	if s.wgMgr.IsConnected() {
		snap := s.agent.Snapshot()
		if vpn, ok := snap["vpn"].(state.VPNStatus); ok && vpn.Connected {
			_ = s.apiClient.DeleteConnection(ctx, vpn.ServerID)
		}
		s.wgMgr.Disconnect()
		_ = s.guard.Disable()
	}

	// Clean up mesh.
	_ = s.apiClient.DeleteAutoMesh(ctx)

	// Stop exit proxy.
	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
	}

	// Clear local forwarder upstream.
	s.localFwd.SetUpstream("", 0)

	if err := s.authMgr.Clear(); err != nil {
		slog.Warn("failed to clear stored tokens on logout", "err", err)
	}
	s.agent.SetVPN(state.VPNStatus{})
	s.agent.SetMesh(state.MeshStatus{})
	s.agent.SetProtection(state.ProtectionStatus{})

	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	_, err := s.authMgr.RefreshNow(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	t := s.authMgr.Snapshot()
	expiresIn := int64(0)
	if t.ExpiresAt > 0 {
		expiresIn = t.ExpiresAt - time.Now().Unix()
	}
	writeJSON(w, map[string]any{"ok": true, "expires_in": expiresIn})
}

// refreshAuthToken is kept as a thin wrapper for code paths that still need
// the legacy (expiresIn, error) signature. New code should use authMgr.
func (s *Server) refreshAuthToken(ctx context.Context) (int, error) {
	_, err := s.authMgr.RefreshNow(ctx)
	if err != nil {
		return 0, err
	}
	t := s.authMgr.Snapshot()
	if t.ExpiresAt == 0 {
		return 0, nil
	}
	return int(t.ExpiresAt - time.Now().Unix()), nil
}

// ----- servers -----

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.LoggedIn() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	servers, err := s.listServersCached(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if servers == nil {
		servers = []apiClient.Server{}
	}
	writeJSON(w, servers)
}

func (s *Server) listServersCached(ctx context.Context, force bool) ([]apiClient.Server, error) {
	const freshTTL = 5 * time.Minute
	const staleTTL = 1 * time.Hour

	s.serversMu.Lock()
	if !force && len(s.serversCache) > 0 {
		age := time.Since(s.serversCacheAt)
		cached := cloneServers(s.serversCache)
		if age < freshTTL {
			s.serversMu.Unlock()
			return cached, nil
		}
		if age < staleTTL {
			if !s.serversRefreshActive {
				s.serversRefreshActive = true
				go s.refreshServersCache(context.Background())
			}
			s.serversMu.Unlock()
			return cached, nil
		}
	}
	s.serversMu.Unlock()

	servers, err := s.apiClient.ListServers(ctx)
	if err != nil {
		s.serversMu.Lock()
		cached := cloneServers(s.serversCache)
		s.serversMu.Unlock()
		if len(cached) > 0 {
			return cached, nil
		}
		return nil, err
	}
	s.setServersCache(servers)
	return cloneServers(servers), nil
}

func (s *Server) refreshServersCache(ctx context.Context) {
	defer func() {
		s.serversMu.Lock()
		s.serversRefreshActive = false
		s.serversMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	servers, err := s.apiClient.ListServers(ctx)
	if err != nil {
		slog.Warn("servers cache refresh failed", "err", err)
		return
	}
	s.setServersCache(servers)
}

func (s *Server) setServersCache(servers []apiClient.Server) {
	s.serversMu.Lock()
	defer s.serversMu.Unlock()
	s.serversCache = cloneServers(servers)
	s.serversCacheAt = time.Now()
	go persistServersCache(servers)
}

func (s *Server) loadServersCacheFromDisk() {
	path, err := serversCachePath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cache struct {
		Servers  []apiClient.Server `json:"servers"`
		CachedAt time.Time          `json:"cached_at"`
	}
	if err := json.Unmarshal(data, &cache); err != nil || len(cache.Servers) == 0 {
		return
	}
	s.serversMu.Lock()
	s.serversCache = cloneServers(cache.Servers)
	s.serversCacheAt = cache.CachedAt
	s.serversMu.Unlock()
}

func persistServersCache(servers []apiClient.Server) {
	if len(servers) == 0 {
		return
	}
	path, err := serversCachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(struct {
		Servers  []apiClient.Server `json:"servers"`
		CachedAt time.Time          `json:"cached_at"`
	}{
		Servers:  cloneServers(servers),
		CachedAt: time.Now(),
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

func serversCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "midorivpn", "servers.json"), nil
}

func cloneServers(in []apiClient.Server) []apiClient.Server {
	if in == nil {
		return nil
	}
	out := make([]apiClient.Server, len(in))
	copy(out, in)
	return out
}

// ----- vpn -----

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	connections, err := s.apiClient.ListConnections(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if connections == nil {
		connections = []apiClient.Connection{}
	}
	writeJSON(w, connections)
}

func (s *Server) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	connID := r.PathValue("id")
	if connID == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if err := s.apiClient.DeleteConnection(r.Context(), connID); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleVPNConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "server_id required")
		return
	}
	// Validate server_id is a UUID to prevent path injection to the backend API.
	if !isValidUUID(req.ServerID) {
		writeError(w, http.StatusBadRequest, "invalid server_id format")
		return
	}

	// "Last request wins": cancel any in-progress connect and take exclusive ownership.
	s.connectMu.Lock()
	if s.connectCancel != nil {
		s.connectCancel() // cancel previous in-flight connect
	}
	s.connectSeq++
	mySeq := s.connectSeq
	ctx, cancel := context.WithCancel(r.Context())
	s.connectCancel = cancel
	s.connectMu.Unlock()

	// Release ownership on exit; always cancel the derived context.
	defer func() {
		cancel()
		s.connectMu.Lock()
		if s.connectSeq == mySeq {
			s.connectCancel = nil
		}
		s.connectMu.Unlock()
	}()

	// cleanupCtx is used for backend cleanup after a failure so that it is not
	// affected by a cancelled ctx (e.g. superseded by a newer connect request).
	cleanupCtx := context.Background()

	// Ensure we have a valid access token before starting the connect sequence.
	// GetValidToken refreshes lazily (only if near expiry) and, on a definitive
	// 4xx from the IdP, clears the session and notifies the UI via SSE.
	// For transient network errors we return 502 so the UI can retry without
	// losing the session — we must NOT call Clear() on every refresh failure.
	token, tokenErr := s.authMgr.GetValidToken(ctx)
	if tokenErr != nil {
		slog.Warn("vpn connect: failed to get valid token", "err", tokenErr)
		// DefiniteAuthError: session already cleared inside GetValidToken→RefreshNow.
		// Transient error: return 502 so the UI shows a retry-able error.
		writeError(w, http.StatusBadGateway, "auth: "+tokenErr.Error())
		return
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated: please sign in")
		return
	}

	// Generate keypair.
	kp, err := s.apiClient.GenerateKeypair(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "keypair: "+err.Error())
		return
	}

	// Create connection.
	connCfg, err := s.apiClient.CreateConnection(ctx, req.ServerID, kp.PublicKey, "desktop")
	if err != nil {
		writeError(w, http.StatusBadGateway, "connect: "+err.Error())
		return
	}

	// Get server details.
	servers, err := s.apiClient.ListServers(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "list servers: "+err.Error())
		return
	}
	var server *apiClient.Server
	for i := range servers {
		if servers[i].ID == req.ServerID {
			server = &servers[i]
			break
		}
	}
	if server == nil {
		// Peer was registered but we cannot find the server — roll back.
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !server.SupportsWireGuard {
		writeError(w, http.StatusBadRequest, "server does not support WireGuard full tunnel")
		return
	}

	// Bring up WireGuard.
	endpoint := fmt.Sprintf("%s:%d", server.Endpoint, server.WGPort)
	if server.Endpoint == "" {
		endpoint = fmt.Sprintf("%s:%d", server.Host, server.WGPort)
	}
	endpoint = splitHost(endpoint)
	endpoint = fmt.Sprintf("%s:%d", endpoint, server.WGPort)
	assignedIP := normalizeAssignedIP(connCfg.PeerIP)
	serverPublicKey := server.PublicKey
	if connCfg.ServerPublicKey != "" {
		serverPublicKey = connCfg.ServerPublicKey
	}
	serverEndpoint := endpoint
	if connCfg.ServerEndpoint != "" {
		serverEndpoint = connCfg.ServerEndpoint
	}

	// Use DNS provided by the server; fall back to Cloudflare if the server
	// doesn't specify one, so that full-tunnel mode doesn't break DNS.
	dnsServers := splitCSV(connCfg.DNS)
	slog.Info("vpn connect: parsed DNS", "raw", connCfg.DNS, "parsed", dnsServers, "count", len(dnsServers))
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1", "1.0.0.1"}
		slog.Info("vpn connect: using Cloudflare DNS fallback", "servers", dnsServers)
	}
	dnsServers = sanitizeDNS(dnsServers)

	wgCfg := &wg.Config{
		PrivateKey: kp.PrivateKey,
		PublicKey:  serverPublicKey,
		Endpoint:   serverEndpoint,
		AssignedIP: assignedIP,
		DNS:        dnsServers,
	}

	if err := s.wgMgr.Connect(wgCfg); err != nil {
		// Clean up peer on failure; use cleanupCtx so it runs even if ctx was cancelled.
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		if isTunPermissionError(err) {
			writeError(w, http.StatusForbidden,
				"wg connect: permisos insuficientes para crear TUN. Reaplica permisos en MidoriVPN o ejecuta: sudo setcap cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep /usr/local/bin/midorivpn-agent")
			return
		}
		writeError(w, http.StatusInternalServerError, "wg connect: "+err.Error())
		return
	}
	if err := s.guard.Enable(s.netguardScope(serverEndpoint, assignedIP)); err != nil {
		s.wgMgr.Disconnect()
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		s.agent.SetProtection(state.ProtectionStatus{LastError: err.Error()})
		writeError(w, http.StatusInternalServerError, "kill switch: "+err.Error())
		return
	}

	// Verify we were not superseded by a newer connect request that took ownership.
	// If we were, tear down the tunnel we just brought up so the newer request can
	// establish its own clean state.
	s.connectMu.Lock()
	superseded := s.connectSeq != mySeq
	s.connectMu.Unlock()
	if superseded {
		slog.Info("vpn connect: superseded by newer request, rolling back", "seq", mySeq)
		s.wgMgr.Disconnect()
		_ = s.guard.Disable()
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusConflict, "superseded by a newer connect request")
		return
	}

	serverPublicIP := server.Endpoint
	if serverPublicIP == "" {
		serverPublicIP = server.Host
	}
	s.agent.SetVPN(state.VPNStatus{
		Connected:      true,
		ServerName:     server.Name,
		ServerID:       connCfg.PeerID,
		AssignedIP:     assignedIP,
		ServerPublicIP: serverPublicIP,
		ServerEndpoint: serverEndpoint,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{
		KillSwitchActive: true,
		DNSProtected:     s.wgMgr.DNSProtected(),
		Mode:             "wireguard",
	})

	writeJSON(w, map[string]any{
		"ok":          true,
		"assigned_ip": assignedIP,
		"server":      server.Name,
	})
}

func (s *Server) handleVPNDisconnect(w http.ResponseWriter, r *http.Request) {
	s.stopVPNStatsLoop()
	snap := s.agent.Snapshot()
	serverID := ""
	if vpn, ok := snap["vpn"].(state.VPNStatus); ok {
		serverID = vpn.ServerID
	}
	// Disconnect locally and respond immediately — don't block on cloud API.
	s.wgMgr.Disconnect()
	_ = s.guard.Disable()
	s.agent.SetVPN(state.VPNStatus{Connected: false})
	s.agent.SetProtection(state.ProtectionStatus{})
	writeJSON(w, map[string]bool{"ok": true})
	// Deregister peer from backend in the background.
	if serverID != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.apiClient.DeleteConnection(ctx, serverID)
		}()
	}
}

// ----- mesh -----

func (s *Server) handleMeshEnable(w http.ResponseWriter, r *http.Request) {
	if err := s.enableMesh(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// User explicitly enabled mesh — clear any prior "start disabled" pref so
	// future agent restarts auto-enable.
	if s.settings != nil {
		if err := s.settings.Update(func(c *settings.Settings) { c.Mesh.StartDisabled = false }); err != nil {
			slog.Warn("settings: failed to persist mesh.start_disabled=false", "err", err)
		}
	}
	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	// Apply host firewall rules for mesh traffic + local RPC.
	// Mesh activation still succeeds if this fails, but we return a warning
	// so the UI/user can verify why no firewalld delta is visible.
	firewallWarning := ""
	fwCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	iface := "wg0"
	if s.wgMgr != nil && s.wgMgr.InterfaceName() != "" {
		iface = s.wgMgr.InterfaceName()
	}
	if err := firewall.Allow(fwCtx, firewall.Scope{
		Name:              "mesh",
		Interface:         iface,
		RPCPort:           s.port,
		MeshDestinationIP: meshState.MeshIP,
		MeshPeerIPs:       peerMeshIPs(meshState.Peers),
		MeshProxyPort:     meshState.ExitNodePort,
	}); err != nil {
		firewallWarning = err.Error()
		slog.Warn("firewall allow failed (mesh still up)", "err", err)
	}
	writeJSON(w, map[string]any{
		"ok":               true,
		"mesh_ip":          meshState.MeshIP,
		"proxy_port":       meshState.ExitNodePort,
		"local_proxy_port": localFwdPort,
		"peers":            meshState.Peers,
		"firewall_warning": firewallWarning,
	})
}

// enableMesh activates this node as a mesh member + exit node.
// It is idempotent: calling it when mesh is already active is a no-op.
func (s *Server) enableMesh(ctx context.Context) error {
	// Already active — nothing to do.
	if snap := s.agent.Snapshot(); func() bool {
		m, _ := snap["mesh"].(state.MeshStatus)
		return m.Active
	}() {
		return nil
	}

	node, err := s.apiClient.ActivateNode(ctx)
	if err != nil {
		return err
	}

	const proxyPort = 1080
	if err := s.apiClient.RegisterExitNode(ctx, node.MeshID, "socks5", proxyPort, true, true); err != nil {
		slog.Warn("mesh: failed to register exit node", "err", err)
	}

	// Enable IP forwarding + iptables NAT so mesh peers can route all their
	// traffic through this node and appear with this node's public IP.
	if err := mesh.EnableNAT(""); err != nil {
		slog.Warn("mesh: NAT setup failed (may need root)", "err", err)
	}

	// Start exit proxy for mesh peers if not already running.
	if s.proxyCtx == nil {
		proxyCtx, cancel := context.WithCancel(context.Background())
		s.proxyCtx = cancel
		p := proxy.NewSOCKS5(fmt.Sprintf(":%d", proxyPort))
		s.socks5Srv = p
		go func() {
			if err := p.Start(proxyCtx); err != nil {
				slog.Error("mesh socks5 exit proxy error", "err", err)
			}
		}()
	}

	s.agent.SetMesh(state.MeshStatus{
		Active:       true,
		MeshID:       node.MeshID,
		MeshIP:       node.MeshIP,
		PublicIP:     node.PublicIP,
		IsExitNode:   true,
		ExitNodePort: proxyPort,
		Peers:        node.Peers,
	})

	s.refreshGuardForCurrentVPN()

	slog.Info("mesh enabled", "mesh_ip", node.MeshIP, "peers", len(node.Peers))
	return nil
}

func (s *Server) handleMeshDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.DeactivateNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// User explicitly turned mesh off — remember so next agent boot does not
	// auto-re-enable.
	if s.settings != nil {
		if err := s.settings.Update(func(c *settings.Settings) { c.Mesh.StartDisabled = true }); err != nil {
			slog.Warn("settings: failed to persist mesh.start_disabled=true", "err", err)
		}
	}

	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
		s.proxySrv = nil
		s.socks5Srv = nil
	}

	// Remove Mesh NAT and restore ip_forward immediately. Do not wait for
	// app shutdown when the user explicitly disables Mesh.
	mesh.DisableNATAndRestore(r.Context(), "")

	// Roll back firewall rules we installed on enable. Tagged rules only.
	go func() {
		fwCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		iface := "wg0"
		if s.wgMgr != nil && s.wgMgr.InterfaceName() != "" {
			iface = s.wgMgr.InterfaceName()
		}
		sysstate.Global.RevertByPrefix(fwCtx, "firewall:mesh:")
		if err := firewall.Cleanup(fwCtx, iface); err != nil {
			slog.Debug("firewall cleanup failed", "err", err)
		}
	}()

	// Clear any exit node routing.
	s.localFwd.SetUpstream("", 0)

	s.agent.SetMesh(state.MeshStatus{Active: false})
	s.refreshGuardForCurrentVPN()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleListExitNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.apiClient.ListExitNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if nodes == nil {
		nodes = []apiClient.ExitNode{}
	}
	writeJSON(w, nodes)
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MeshIP      string `json:"mesh_ip"`
		ProxyScheme string `json:"proxy_scheme"`
		ProxyPort   int    `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MeshIP == "" || req.ProxyPort <= 0 {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ProxyScheme == "" {
		req.ProxyScheme = "socks5"
	}
	if req.ProxyScheme != "socks5" && req.ProxyScheme != "http-connect" {
		writeError(w, http.StatusBadRequest, "unsupported proxy_scheme")
		return
	}
	if err := s.apiClient.SetExitNode(r.Context(), req.MeshIP, req.ProxyScheme, req.ProxyPort); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	if req.ProxyScheme == "http-connect" {
		s.localFwd.SetUpstream(req.MeshIP, req.ProxyPort)
	} else {
		s.localFwd.SetUpstream("", 0)
	}

	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	meshState.ExitNodeHost = req.MeshIP
	meshState.ExitNodePort = req.ProxyPort
	meshState.ExitNodeScheme = req.ProxyScheme
	meshState.FullTunnel = true
	s.agent.SetMesh(meshState)

	writeJSON(w, map[string]any{
		"ok":               true,
		"local_proxy_port": localFwdPort,
		"proxy_scheme":     req.ProxyScheme,
	})
}

func (s *Server) handleMeshFullTunnelEnable(w http.ResponseWriter, r *http.Request) {
	s.handleSetExitNode(w, r)
}

func (s *Server) handleMeshFullTunnelDisable(w http.ResponseWriter, r *http.Request) {
	s.handleClearExitNode(w, r)
}

func (s *Server) handleClearExitNode(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.ClearExitNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.localFwd.SetUpstream("", 0)
	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	meshState.ExitNodeHost = ""
	meshState.ExitNodePort = 0
	meshState.ExitNodeScheme = ""
	meshState.FullTunnel = false
	s.agent.SetMesh(meshState)
	writeJSON(w, map[string]bool{"ok": true})
}

// ----- public IP -----

// handlePublicIP fetches the current public IP of this machine.
// When VPN is connected (wg0 with AllowedIPs=0.0.0.0/0) the request exits
// through the WireGuard tunnel. If an exit node is active, the response IP
// will match the exit node's public IP.
func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("User-Agent", "midorivpn-agent/1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cannot reach IP check service: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))

	writeJSON(w, map[string]any{
		"ip":               ip,
		"exit_node_active": s.localFwd.Active(),
		"exit_node":        s.localFwd.Upstream(),
	})
}

// ----- helpers -----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func splitHost(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func normalizeAssignedIP(assignedIP string) string {
	for strings.HasSuffix(assignedIP, "/32/32") {
		assignedIP = strings.TrimSuffix(assignedIP, "/32")
	}
	if assignedIP != "" && !strings.Contains(assignedIP, "/") {
		assignedIP += "/32"
	}
	return assignedIP
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// isReservedIP returns true for IP addresses that must never be used as DNS
// resolvers supplied by the backend: loopback, link-local, private RFC-1918,
// CGNAT (100.64/10), and the unspecified address.  Accepting these from the
// API would allow the server to redirect DNS queries to internal infrastructure
// or to the local network, bypassing the intent of the VPN DNS protection.
func isReservedIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return true // unparseable → treat as unsafe
	}
	reserved := []string{
		"0.0.0.0/8",          // unspecified / this-network
		"10.0.0.0/8",         // RFC-1918 private
		"100.64.0.0/10",      // CGNAT (also used by WireGuard mesh)
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local
		"172.16.0.0/12",      // RFC-1918 private
		"192.168.0.0/16",     // RFC-1918 private
		"::1/128",             // IPv6 loopback
		"fe80::/10",           // IPv6 link-local
		"fc00::/7",            // IPv6 unique-local
	}
	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// sanitizeDNS filters the DNS list provided by the backend, removing any
// entries that are reserved/private (which could redirect DNS to internal
// infrastructure or the local network).  If filtering leaves an empty list,
// the Cloudflare fallback is returned instead so full-tunnel mode stays usable.
func sanitizeDNS(servers []string) []string {
	safe := make([]string, 0, len(servers))
	for _, s := range servers {
		if isReservedIP(s) {
			slog.Warn("vpn connect: rejecting reserved DNS address from backend", "addr", s)
			continue
		}
		safe = append(safe, s)
	}
	if len(safe) == 0 {
		slog.Warn("vpn connect: all backend DNS entries rejected; falling back to Cloudflare")
		return []string{"1.1.1.1", "1.0.0.1"}
	}
	return safe
}

func isTunPermissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "create tun") && strings.Contains(msg, "operation not permitted")
}

func (s *Server) netguardScope(endpoint, assignedIP string) netguard.Scope {
	scope := netguard.Scope{
		TunnelIface: s.wgMgr.InterfaceName(),
		Endpoint:    endpoint,
		APIURL:      s.apiURL,
		AssignedIP:  assignedIP,
	}
	snap := s.agent.Snapshot()
	if meshState, ok := snap["mesh"].(state.MeshStatus); ok && meshState.Active {
		scope.MeshPeerIPs = peerMeshIPs(meshState.Peers)
	}
	return scope
}

func (s *Server) refreshGuardForCurrentVPN() {
	if s.guard == nil || !s.guard.Active() {
		return
	}
	snap := s.agent.Snapshot()
	vpn, ok := snap["vpn"].(state.VPNStatus)
	if !ok || !vpn.Connected {
		return
	}
	if err := s.guard.Enable(s.netguardScope(vpn.ServerEndpoint, vpn.AssignedIP)); err != nil {
		slog.Warn("kill switch refresh failed", "err", err)
		protection, _ := snap["protection"].(state.ProtectionStatus)
		protection.LastError = err.Error()
		s.agent.SetProtection(protection)
	}
}

func peerMeshIPs(peers []apiClient.Peer) []string {
	out := make([]string, 0, len(peers))
	for _, peer := range peers {
		ip := strings.TrimSpace(peer.MeshIP)
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// isValidUUID returns true if s looks like a canonical UUID
// (8-4-4-4-12 hex digits).  This prevents path-injection into backend URLs.
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// ----- settings -----

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, s.settings.Get())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings store unavailable")
		return
	}
	var req settings.Settings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.settings.Update(func(c *settings.Settings) { *c = req }); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, s.settings.Get())
}

// gracefulShutdown tears down active mesh / VPN / proxy resources before the
// HTTP server stops. Each step is bounded by its own short timeout so a
// hanging backend cannot stall agent exit beyond a few seconds.
func (s *Server) gracefulShutdown() {
	defer func() {
		// Never let a panic in cleanup keep the agent alive.
		if r := recover(); r != nil {
			slog.Error("gracefulShutdown panic", "recover", r)
		}
	}()

	// Disconnect VPN tunnel if up.
	s.stopVPNStatsLoop()
	if s.wgMgr != nil && s.wgMgr.IsConnected() {
		slog.Info("shutdown: disconnecting WireGuard tunnel")
		s.wgMgr.Disconnect()
	}
	if s.guard != nil {
		_ = s.guard.Disable()
	}

	// Stop exit proxy / SOCKS5 listener.
	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
	}
	if s.localFwd != nil {
		s.localFwd.SetUpstream("", 0)
	}

	// Best-effort: tell the backend we're going away so peers don't see us
	// as a stale node. Short timeout so a 504 doesn't block exit.
	if s.apiClient != nil && s.authMgr != nil && s.authMgr.LoggedIn() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.apiClient.DeactivateNode(ctx); err != nil {
			slog.Debug("shutdown: mesh deactivate failed (best effort)", "err", err)
		}
	}
}

func (s *Server) startVPNStatsLoop() {
	s.vpnStatsMu.Lock()
	// Stop any existing loop first so reconnects always get a fresh goroutine
	// with up-to-date state rather than silently reusing the old one.
	if s.vpnStatsCancel != nil {
		s.vpnStatsCancel()
		s.vpnStatsCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.vpnStatsCancel = cancel
	s.vpnStatsMu.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		s.updateVPNByteCounters()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.updateVPNByteCounters()
			}
		}
	}()
}

func (s *Server) stopVPNStatsLoop() {
	s.vpnStatsMu.Lock()
	defer s.vpnStatsMu.Unlock()
	if s.vpnStatsCancel != nil {
		s.vpnStatsCancel()
		s.vpnStatsCancel = nil
	}
}

func (s *Server) updateVPNByteCounters() {
	tx, rx, ok := s.wgMgr.ByteCounters()
	if !ok {
		return
	}

	snap := s.agent.Snapshot()
	vpn, ok := snap["vpn"].(state.VPNStatus)
	if !ok || !vpn.Connected {
		return
	}
	if vpn.BytesSent == tx && vpn.BytesRecv == rx {
		return
	}
	vpn.BytesSent = tx
	vpn.BytesRecv = rx
	s.agent.SetVPN(vpn)
}

// Shutdown performs an orderly cleanup of every system mutation made by the
// agent: VPN disconnect (restores resolv.conf, removes kill switch), mesh NAT
// disable, firewall rule cleanup, and any other mutations recorded in
// sysstate.Global. Safe to call more than once; idempotent and best-effort.
func (s *Server) Shutdown(ctx context.Context) {
	slog.Info("agent: starting graceful shutdown cleanup")

	// 1. Disconnect VPN — this calls Guard.Disable() and restores resolv.conf.
	if s.wgMgr != nil {
		s.wgMgr.Disconnect()
	}

	// 2. Disable mesh NAT and restore ip_forward if Mesh had changed it.
	mesh.DisableNATAndRestore(ctx, "")

	// 3. Disable kill switch if still active (Guard.Disable removes inet midorivpn_guard).
	if s.guard != nil && s.guard.Active() {
		if err := s.guard.Disable(); err != nil {
			slog.Warn("shutdown: guard disable failed", "err", err)
		}
	}

	// 4. Stop local forwarder and SOCKS5 proxy.
	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
	}

	// 5. Revert all registered sysstate mutations (firewall rules, ip_forward,
	//    any future mutations). This is the safety net for anything above that
	//    might have already been cleaned up — RevertAll is idempotent.
	sysstate.Global.RevertAll(ctx)

	// 6. Optional self-revoke file capabilities.
	// By default this is disabled because desktop flows may restart the agent
	// in-process (e.g. after granting permissions), and revoking here would
	// immediately break the next spawn. Desktop shells should handle capability
	// revocation on full app exit.
	if os.Getenv("MIDORIVPN_REVOKE_CAPS_ON_SHUTDOWN") == "1" {
		s.revokeSelfCaps()
	}

	slog.Info("agent: graceful shutdown cleanup complete")
}

// revokeSelfCaps removes file capabilities from the agent binary itself.
// It tries two approaches in order:
//  1. `sudo setcap -r <self>` — requires a NOPASSWD sudoers rule (see packaging).
//  2. `pkexec setcap -r <self>` — only works when a display + polkit agent is available.
func (s *Server) revokeSelfCaps() {
	self, err := os.Executable()
	if err != nil {
		slog.Warn("shutdown: cannot determine agent path, skipping cap revoke", "err", err)
		return
	}

	setcap := ""
	for _, p := range []string{"/sbin/setcap", "/usr/sbin/setcap"} {
		if _, err := os.Stat(p); err == nil {
			setcap = p
			break
		}
	}
	if setcap == "" {
		slog.Warn("shutdown: setcap not found, skipping cap revoke")
		return
	}

	// Try sudo first (no display needed, works from terminal kill).
	revokeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(revokeCtx, "sudo", setcap, "-r", self).CombinedOutput(); err == nil {
		slog.Info("shutdown: file capabilities revoked via sudo setcap -r")
		return
	} else {
		slog.Debug("shutdown: sudo setcap -r failed (no sudoers rule?)", "err", err, "out", string(out))
	}

	// Fallback: pkexec (needs display — works when closed from tray).
	pkCtx, pkCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pkCancel()
	if out, err := exec.CommandContext(pkCtx, "pkexec", setcap, "-r", self).CombinedOutput(); err != nil {
		slog.Warn("shutdown: pkexec setcap -r also failed; caps remain", "err", err, "out", string(out))
	} else {
		slog.Info("shutdown: file capabilities revoked via pkexec setcap -r")
	}
}

// Ensure netguard and mesh are referenced so the compiler sees the import.
var _ = netguard.New
var _ = mesh.DisableNAT
