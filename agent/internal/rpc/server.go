// Package rpc implements the local HTTP API server that the Tauri shell and
// Vue UI use to communicate with the Go agent. It also serves an SSE stream
// for real-time state updates.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/auth"
	"github.com/goastian/midorivpn-agent/internal/caps"
	"github.com/goastian/midorivpn-agent/internal/config"
	"github.com/goastian/midorivpn-agent/internal/netguard"
	"github.com/goastian/midorivpn-agent/internal/proxy"
	"github.com/goastian/midorivpn-agent/internal/settings"
	"github.com/goastian/midorivpn-agent/internal/state"
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
	pendingOAuth          map[string]pendingOAuthEntry // state → PKCE verifier + expiry
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

	// meshMu serializes concurrent enableMesh calls so AutoEnableMesh and the
	// frontend cannot race and double-activate the mesh node.
	meshMu sync.Mutex

	allowMissingAgentTokenForDev bool
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

		pendingOAuth:          make(map[string]pendingOAuthEntry),
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

// SetAllowMissingAgentTokenForDev enables the legacy no-token RPC mode for
// local development only. Production launchers must pass a token.
func (s *Server) SetAllowMissingAgentTokenForDev(allow bool) {
	s.allowMissingAgentTokenForDev = allow
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
	if !caps.HasNetAdmin() {
		slog.Info("auto-mesh: skipped (CAP_NET_ADMIN not granted)")
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
		if !caps.HasNetAdmin() {
			slog.Info("auto-mesh: aborted (CAP_NET_ADMIN no longer present)")
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
		if !caps.HasNetAdmin() {
			slog.Info("auto-mesh on login: skipped (CAP_NET_ADMIN not granted)")
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
