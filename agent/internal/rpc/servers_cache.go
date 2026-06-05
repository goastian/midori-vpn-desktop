package rpc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

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
	// Leave serversCacheAt at zero so the next list request always triggers a
	// background refresh against the API. The disk data is kept only as a
	// fallback in case the first network call fails (e.g. offline startup).
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
