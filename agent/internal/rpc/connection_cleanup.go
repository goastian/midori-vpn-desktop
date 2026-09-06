package rpc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

const (
	connectionCleanupInterval = 5 * time.Second
	connectionCleanupTimeout  = 10 * time.Second
	connectionCleanupBatch    = 8
)

// queueConnectionCleanup must complete before local tunnel teardown. The
// backend DELETE is idempotent, so retaining the peer ID across failures and
// process restarts is both safe and sufficient to converge.
func (s *Server) queueConnectionCleanup(peerID string) error {
	if peerID == "" {
		return nil
	}
	if s.connectionCleanup == nil {
		return fmt.Errorf("pending connection cleanup store is unavailable")
	}
	if err := s.connectionCleanup.Add(peerID); err != nil {
		return fmt.Errorf("persist pending connection cleanup: %w", err)
	}
	s.wakeConnectionCleanup()
	return nil
}

func (s *Server) wakeConnectionCleanup() {
	if s.connectionCleanupWake == nil {
		return
	}
	select {
	case s.connectionCleanupWake <- struct{}{}:
	default:
	}
}

func (s *Server) runConnectionCleanup(ctx context.Context) {
	ticker := time.NewTicker(connectionCleanupInterval)
	defer ticker.Stop()
	s.wakeConnectionCleanup()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.connectionCleanupWake:
		}
		if s.authMgr == nil || !s.authMgr.LoggedIn() {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, connectionCleanupTimeout)
		remaining := s.drainConnectionCleanup(attemptCtx)
		cancel()
		if remaining > 0 {
			slog.Warn("backend VPN cleanup remains pending", "pending_count", remaining)
		}
	}
}

// drainConnectionCleanup makes one bounded pass. Entries leave disk only
// after the backend accepts their DELETE; failures remain available to the
// next tick or process start.
func (s *Server) drainConnectionCleanup(ctx context.Context) int {
	if s.connectionCleanup == nil || s.apiClient == nil {
		return 0
	}
	peerIDs := s.connectionCleanup.List()
	if len(peerIDs) > connectionCleanupBatch {
		peerIDs = peerIDs[:connectionCleanupBatch]
	}
	for _, peerID := range peerIDs {
		if ctx.Err() != nil {
			break
		}
		if err := s.apiClient.DeleteConnection(ctx, peerID); err != nil {
			slog.Warn("backend VPN cleanup attempt failed", "code", "delete_connection_failed", "status", apiClient.ErrorStatus(err))
			continue
		}
		if err := s.connectionCleanup.Remove(peerID); err != nil {
			slog.Error("backend VPN cleanup succeeded but durable entry could not be cleared", "error", err)
		}
	}
	return len(s.connectionCleanup.List())
}
