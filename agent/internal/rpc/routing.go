package rpc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

var allowedDesktopOrigins = map[string]struct{}{
	"tauri://localhost":     {},
	"http://localhost:1420": {},
}

const defaultCORSOrigin = "tauri://localhost"

func constantTimeTokenEqual(incoming, expected string) bool {
	incomingSum := sha256.Sum256([]byte(incoming))
	expectedSum := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(incomingSum[:], expectedSum[:]) == 1
}

func setLocalSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func resolveAgentToken(allowMissingForDev bool) (string, error) {
	token := os.Getenv("MIDORIVPN_AGENT_TOKEN")
	if token == "" && !allowMissingForDev {
		return "", fmt.Errorf("MIDORIVPN_AGENT_TOKEN is required")
	}
	return token, nil
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func withLocalCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setLocalSecurityHeaders(w)
		corsOrigin := defaultCORSOrigin
		if origin := r.Header.Get("Origin"); origin != "" {
			if _, ok := allowedDesktopOrigins[origin]; ok {
				corsOrigin = origin
			} else if r.Method == http.MethodOptions {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", corsOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Agent-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func requireLocalAuth(h http.Handler, agentToken string, allowQueryToken bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			h.ServeHTTP(w, r)
			return
		}

		if !isLoopbackRemote(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			if _, ok := allowedDesktopOrigins[origin]; !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		if agentToken != "" {
			incoming := ""
			if allowQueryToken {
				incoming = r.URL.Query().Get("token")
			}
			if incoming == "" {
				incoming = r.Header.Get("X-Agent-Token")
			}
			if !constantTimeTokenEqual(incoming, agentToken) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

func (s *Server) newMux(agentToken string) http.Handler {
	mux := http.NewServeMux()
	wrap := func(h http.Handler) http.Handler {
		return requireLocalAuth(withLocalCORS(h), agentToken, false)
	}
	wrapSSE := func(h http.Handler) http.Handler {
		return requireLocalAuth(withLocalCORS(h), agentToken, true)
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

	mux.Handle("GET /settings", wrap(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("PUT /settings", wrap(http.HandlerFunc(s.handlePutSettings)))
	mux.Handle("POST /settings", wrap(http.HandlerFunc(s.handlePutSettings)))
	mux.Handle("GET /mesh/exit-nodes", wrap(http.HandlerFunc(s.handleListExitNodes)))
	mux.Handle("POST /mesh/exit-node", wrap(http.HandlerFunc(s.handleSetExitNode)))
	mux.Handle("DELETE /mesh/exit-node", wrap(http.HandlerFunc(s.handleClearExitNode)))
	mux.Handle("POST /mesh/full-tunnel/enable", wrap(http.HandlerFunc(s.handleMeshFullTunnelEnable)))
	mux.Handle("POST /mesh/full-tunnel/disable", wrap(http.HandlerFunc(s.handleMeshFullTunnelDisable)))

	mux.Handle("GET /public-ip", wrap(http.HandlerFunc(s.handlePublicIP)))
	mux.Handle("GET /dns/status", wrap(http.HandlerFunc(s.handleDNSStatus)))

	mux.Handle("POST /oauth/start", wrap(http.HandlerFunc(s.handleOAuthStart)))
	mux.Handle("GET /oauth/callback", http.HandlerFunc(s.handleOAuthCallback))

	return mux
}

// Start begins serving. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	agentToken, err := resolveAgentToken(s.allowMissingAgentTokenForDev)
	if err != nil {
		return err
	}
	if agentToken == "" {
		slog.Warn("MIDORIVPN_AGENT_TOKEN is not set; token enforcement disabled for development")
	}

	go func() {
		if err := s.localFwd.Start(ctx); err != nil {
			slog.Error("local forwarder error", "err", err)
		}
	}()

	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:           s.newMux(agentToken),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
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
