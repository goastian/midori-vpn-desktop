package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/goastian/midorivpn-agent/internal/dns"
	"github.com/goastian/midorivpn-agent/internal/rpc"
	"github.com/goastian/midorivpn-agent/internal/state"
)

var errAlreadyRunning = errors.New("agent already running")

func runtimeFile(name string) (string, error) {
	runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR"))
	if runtimeDir == "" {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is required for the browser UI")
	}
	return filepath.Join(runtimeDir, name), nil
}

func browserTokenPath() (string, error) {
	return runtimeFile("midorivpn-agent.token")
}

func ensureBrowserToken() (string, string, error) {
	token := strings.TrimSpace(os.Getenv("MIDORIVPN_AGENT_TOKEN"))
	if token == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", "", fmt.Errorf("generate browser token: %w", err)
		}
		token = hex.EncodeToString(raw)
		if err := os.Setenv("MIDORIVPN_AGENT_TOKEN", token); err != nil {
			return "", "", fmt.Errorf("set browser token: %w", err)
		}
	}
	path, err := browserTokenPath()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("write browser token: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", "", fmt.Errorf("protect browser token: %w", err)
	}
	return token, path, nil
}

func openBrowserUI(port int, token string) error {
	launchPath, err := runtimeFile("midorivpn-launch.html")
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/#/?agent_token=%s", port, token)
	body := "<!doctype html><meta name=referrer content=no-referrer><meta http-equiv=refresh content=\"0;url=" + html.EscapeString(url) + "\"><title>MidoriVPN</title>"
	if err := os.WriteFile(launchPath, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write browser launch file: %w", err)
	}
	if err := os.Chmod(launchPath, 0o600); err != nil {
		return fmt.Errorf("protect browser launch file: %w", err)
	}
	if err := exec.Command("xdg-open", launchPath).Start(); err != nil {
		return fmt.Errorf("open system browser: %w", err)
	}
	return nil
}

func waitAndOpenBrowser(ctx context.Context, port int, token string) {
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			if openErr := openBrowserUI(port, token); openErr != nil {
				slog.Error("cannot open browser UI", "error", openErr)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-timeout.C:
			slog.Error("browser UI did not become ready", "addr", addr)
			return
		case <-ticker.C:
		}
	}
}

func openExistingBrowserUI(port int) error {
	path, err := browserTokenPath()
	if err != nil {
		return err
	}
	token, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read running agent token: %w", err)
	}
	return openBrowserUI(port, strings.TrimSpace(string(token)))
}

func main() {
	port := flag.Int("port", 7071, "local RPC server port")
	logLevel := flag.String("log", "info", "log level: debug|info|warn|error")
	uiDir := flag.String("ui-dir", "", "directory containing the compiled local browser UI")
	openUI := flag.Bool("open-ui", false, "open the local UI in the system browser")
	background := flag.Bool("background", false, "start without opening the browser UI")
	autostart := flag.Bool("autostart", false, "start in background from an XDG autostart entry")
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
		if errors.Is(err, errAlreadyRunning) && *openUI && !*background && !*autostart {
			if openErr := openExistingBrowserUI(*port); openErr != nil {
				slog.Error("cannot open running browser UI", "err", openErr)
				os.Exit(1)
			}
			return
		}
		slog.Error("cannot acquire single-instance lock", "err", err)
		os.Exit(1)
	}
	defer releaseLock()

	if err := dns.RecoverStaleResolvconf(); err != nil {
		slog.Warn("cannot recover DNS state from an unclean previous exit", "err", err)
	}

	var browserTokenFile string
	var browserToken string
	if strings.TrimSpace(*uiDir) != "" {
		browserToken, browserTokenFile, err = ensureBrowserToken()
		if err != nil {
			slog.Error("cannot initialize browser UI session", "err", err)
			os.Exit(1)
		}
		defer os.Remove(browserTokenFile)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ag := state.NewAgent()

	srv, err := rpc.NewServer(ag, *port)
	if err != nil {
		slog.Error("cannot initialize agent", "err", err)
		os.Exit(1)
	}
	srv.SetUIDir(*uiDir)
	srv.SetLifecycle(restartSelf, cancel)
	slog.Info("MidoriVPN agent starting", "port", *port)

	// Run token init and mesh auto-enable concurrently with the RPC listener
	// so the UI can connect immediately without waiting up to 20 s for a
	// slow or unreachable IdP refresh. AutoEnableMesh already polls internally
	// for auth readiness, so ordering relative to Init is safe.
	go func() {
		initCtx, initCancel := context.WithTimeout(ctx, 20*time.Second)
		if err := srv.Init(initCtx); err != nil {
			slog.Warn("agent init reported an error; continuing", "err", err)
		}
		initCancel()

		// Phase 1B: if mesh is configured to auto-start and we have valid auth,
		// kick off mesh enable. Failures are logged; the user can still toggle
		// from the UI. Wrap in a recover so a panic in mesh setup can't crash
		// the whole agent.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("mesh auto-enable panicked", "panic", r)
			}
		}()
		srv.AutoEnableMesh(ctx)
	}()

	if *openUI && !*background && !*autostart {
		go waitAndOpenBrowser(ctx, *port, browserToken)
	}

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
