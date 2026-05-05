// Package rpc implements the local HTTP API server that the Tauri shell and
// Vue UI use to communicate with the Go agent. It also serves an SSE stream
// for real-time state updates.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/proxy"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/wg"
)

// Server is the local RPC HTTP server.
type Server struct {
	agent     *state.Agent
	port      int
	wgMgr     *wg.Manager
	proxySrv  *proxy.Server
	proxyCtx  context.CancelFunc
	apiClient *apiClient.Client

	// Configurable from env / Tauri startup args.
	apiURL  string
	jwksURL string
}

// NewServer creates the RPC server. apiURL defaults to the production backend.
func NewServer(ag *state.Agent, port int) *Server {
	const defaultAPIURL = "https://vpn.astian.org"
	s := &Server{
		agent:  ag,
		port:   port,
		wgMgr:  wg.NewManager(),
		apiURL: defaultAPIURL,
	}
	s.apiClient = apiClient.New(s.apiURL, ag.GetAccessToken)
	return s
}

// Start begins serving. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// CORS middleware for browser calls on localhost.
	withCORS := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "tauri://localhost")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	mux.Handle("GET /status", withCORS(http.HandlerFunc(s.handleStatus)))
	mux.Handle("GET /events", withCORS(http.HandlerFunc(s.handleSSE)))

	mux.Handle("POST /auth/set-tokens", withCORS(http.HandlerFunc(s.handleSetTokens)))
	mux.Handle("DELETE /auth/logout", withCORS(http.HandlerFunc(s.handleLogout)))
	mux.Handle("POST /auth/refresh", withCORS(http.HandlerFunc(s.handleRefreshToken)))

	mux.Handle("GET /servers", withCORS(http.HandlerFunc(s.handleListServers)))

	mux.Handle("POST /vpn/connect", withCORS(http.HandlerFunc(s.handleVPNConnect)))
	mux.Handle("POST /vpn/disconnect", withCORS(http.HandlerFunc(s.handleVPNDisconnect)))

	mux.Handle("POST /mesh/enable", withCORS(http.HandlerFunc(s.handleMeshEnable)))
	mux.Handle("POST /mesh/disable", withCORS(http.HandlerFunc(s.handleMeshDisable)))
	mux.Handle("GET /mesh/exit-nodes", withCORS(http.HandlerFunc(s.handleListExitNodes)))
	mux.Handle("POST /mesh/exit-node", withCORS(http.HandlerFunc(s.handleSetExitNode)))
	mux.Handle("DELETE /mesh/exit-node", withCORS(http.HandlerFunc(s.handleClearExitNode)))

	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
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
	writeJSON(w, s.agent.Snapshot())
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
		Username     string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.agent.SetAuth(state.AuthStatus{
		LoggedIn:     true,
		Username:     req.Username,
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		ExpiresAt:    req.ExpiresAt,
	})

	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Disconnect VPN if connected.
	if s.wgMgr.IsConnected() {
		snap := s.agent.Snapshot()
		if vpn, ok := snap["vpn"].(state.VPNStatus); ok && vpn.Connected {
			_ = s.apiClient.DeleteConnection(ctx, vpn.ServerID)
		}
		s.wgMgr.Disconnect()
	}

	// Clean up mesh.
	_ = s.apiClient.DeleteAutoMesh(ctx)

	// Stop proxy.
	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
	}

	s.agent.SetAuth(state.AuthStatus{LoggedIn: false})
	s.agent.SetVPN(state.VPNStatus{})
	s.agent.SetMesh(state.MeshStatus{})

	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	snap := s.agent.Snapshot()
	auth, _ := snap["auth"].(state.AuthStatus)

	if auth.RefreshToken == "" {
		writeError(w, http.StatusUnauthorized, "no refresh token")
		return
	}

	access, refresh, expiresIn, err := s.apiClient.RefreshToken(r.Context(), auth.RefreshToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	s.agent.SetAuth(state.AuthStatus{
		LoggedIn:     true,
		Username:     auth.Username,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).UnixMilli(),
	})

	writeJSON(w, map[string]any{"ok": true, "expires_in": expiresIn})
}

// ----- servers -----

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.apiClient.ListServers(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"servers": servers})
}

// ----- vpn -----

func (s *Server) handleVPNConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "server_id required")
		return
	}

	ctx := r.Context()

	// Generate keypair.
	kp, err := s.apiClient.GenerateKeypair(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "keypair: "+err.Error())
		return
	}

	// Create connection.
	conn, err := s.apiClient.CreateConnection(ctx, req.ServerID, kp.PublicKey, "desktop")
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
		writeError(w, http.StatusNotFound, "server not found")
		return
	}

	// Bring up WireGuard.
	endpoint := fmt.Sprintf("%s:%d", server.Endpoint, server.WGPort)
	if server.Endpoint == "" {
		endpoint = fmt.Sprintf("%s:%d", server.Host, server.WGPort)
	}
	endpoint = splitHost(endpoint)
	endpoint = fmt.Sprintf("%s:%d", endpoint, server.WGPort)

	wgCfg := &wg.Config{
		PrivateKey: kp.PrivateKey,
		PublicKey:  server.PublicKey,
		Endpoint:   fmt.Sprintf("%s:%d", splitHost(server.Endpoint), server.WGPort),
		AssignedIP: conn.AssignedIP,
	}

	if err := s.wgMgr.Connect(wgCfg); err != nil {
		// Clean up peer on failure.
		_ = s.apiClient.DeleteConnection(ctx, conn.ID)
		writeError(w, http.StatusInternalServerError, "wg connect: "+err.Error())
		return
	}

	s.agent.SetVPN(state.VPNStatus{
		Connected:  true,
		ServerName: server.Name,
		ServerID:   conn.ID,
		AssignedIP: conn.AssignedIP,
	})

	writeJSON(w, map[string]any{
		"ok":          true,
		"assigned_ip": conn.AssignedIP,
		"server":      server.Name,
	})
}

func (s *Server) handleVPNDisconnect(w http.ResponseWriter, r *http.Request) {
	snap := s.agent.Snapshot()
	if vpn, ok := snap["vpn"].(state.VPNStatus); ok && vpn.ServerID != "" {
		_ = s.apiClient.DeleteConnection(r.Context(), vpn.ServerID)
	}
	s.wgMgr.Disconnect()
	s.agent.SetVPN(state.VPNStatus{Connected: false})
	writeJSON(w, map[string]bool{"ok": true})
}

// ----- mesh -----

func (s *Server) handleMeshEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	node, err := s.apiClient.ActivateNode(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	const proxyPort = 8888
	if err := s.apiClient.RegisterExitNode(ctx, proxyPort); err != nil {
		slog.Warn("mesh: failed to register exit node", "err", err)
	}

	// Start local proxy for mesh egress if not already running.
	if s.proxyCtx == nil {
		proxyCtx, cancel := context.WithCancel(context.Background())
		s.proxyCtx = cancel
		p := proxy.New(fmt.Sprintf(":%d", proxyPort), s.jwksURL)
		go func() {
			if err := p.Start(proxyCtx); err != nil {
				slog.Error("mesh proxy error", "err", err)
			}
		}()
	}

	s.agent.SetMesh(state.MeshStatus{
		Active:     true,
		MeshID:     node.MeshID,
		MeshIP:     node.MeshIP,
		PublicIP:   node.PublicIP,
		IsExitNode: true,
		Peers:      node.Peers,
	})

	writeJSON(w, map[string]any{
		"ok":      true,
		"mesh_ip": node.MeshIP,
		"peers":   node.Peers,
	})
}

func (s *Server) handleMeshDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.DeactivateNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
	}

	s.agent.SetMesh(state.MeshStatus{Active: false})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleListExitNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.apiClient.ListExitNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"exit_nodes": nodes})
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyHost string `json:"proxy_host"`
		ProxyPort int    `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.apiClient.SetExitNode(r.Context(), req.ProxyHost, req.ProxyPort); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	snap := s.agent.Snapshot()
	mesh, _ := snap["mesh"].(state.MeshStatus)
	mesh.ExitNodeHost = req.ProxyHost
	mesh.ExitNodePort = req.ProxyPort
	s.agent.SetMesh(mesh)

	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleClearExitNode(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.ClearExitNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	snap := s.agent.Snapshot()
	mesh, _ := snap["mesh"].(state.MeshStatus)
	mesh.ExitNodeHost = ""
	mesh.ExitNodePort = 0
	s.agent.SetMesh(mesh)
	writeJSON(w, map[string]bool{"ok": true})
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
