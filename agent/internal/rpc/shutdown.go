package rpc

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/goastian/midorivpn-agent/internal/mesh"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/sysstate"
)

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
	// Skip when mesh wasn't actually enabled in this session — this
	// prevents the activate/deactivate audit churn that occurs when the
	// agent restarts without ever having activated mesh (e.g. caps not
	// granted, so AutoEnableMesh skipped).
	if s.apiClient != nil && s.authMgr != nil && s.authMgr.LoggedIn() {
		meshActive := false
		if s.agent != nil {
			if m, ok := s.agent.Snapshot()["mesh"].(state.MeshStatus); ok {
				meshActive = m.Active
			}
		}
		if meshActive {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.apiClient.DeactivateNode(ctx); err != nil {
				slog.Debug("shutdown: mesh deactivate failed (best effort)", "err", err)
			}
		}
	}
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
