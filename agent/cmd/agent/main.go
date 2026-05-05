package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ag := state.NewAgent()

	srv := rpc.NewServer(ag, *port)
	slog.Info("MidoriVPN agent starting", "port", *port)

	if err := srv.Start(ctx); err != nil {
		slog.Error("agent exited", "error", err)
		os.Exit(1)
	}
}
