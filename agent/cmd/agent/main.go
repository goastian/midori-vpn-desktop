package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goastian/midorivpn-agent/internal/rpc"
	"github.com/goastian/midorivpn-agent/internal/state"
)

func main() {
	port := flag.Int("port", 7071, "local RPC server port")
	logLevel := flag.String("log", "info", "log level: debug|info|warn|error")
	flag.Parse()

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	releaseLock, err := acquireSingleInstanceLock()
	if err != nil {
		slog.Error("cannot acquire single-instance lock", "err", err)
		os.Exit(1)
	}
	defer releaseLock()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ag := state.NewAgent()

	srv := rpc.NewServer(ag, *port)
	slog.Info("MidoriVPN agent starting", "port", *port)

	// Load persisted OAuth tokens (if any) and run an initial refresh if the
	// stored access token is already in the leeway window. Bounded so a slow
	// IdP cannot block startup forever.
	initCtx, initCancel := context.WithTimeout(ctx, 20*time.Second)
	if err := srv.Init(initCtx); err != nil {
		slog.Warn("agent init reported an error; continuing", "err", err)
	}
	initCancel()

	// Phase 1B: if mesh is configured to auto-start and we have valid auth,
	// kick off mesh enable in background. Failures are logged; the user can
	// still toggle from the UI. Wrap in a recover so a panic in mesh setup
	// can't crash the whole agent.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("mesh auto-enable panicked", "panic", r)
			}
		}()
		srv.AutoEnableMesh(ctx)
	}()

	if err := srv.Start(ctx); err != nil {
		slog.Error("agent exited", "error", err)
		// Even on error, attempt cleanup so we don't leave nft tables / firewall
		// rules behind.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		srv.Shutdown(cleanupCtx)
		os.Exit(1)
	}

	// Context cancelled (SIGINT/SIGTERM): perform graceful cleanup before exit.
	slog.Info("agent: context done, running cleanup")
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cleanupCancel()
	srv.Shutdown(cleanupCtx)
}
