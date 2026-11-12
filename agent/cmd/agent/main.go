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
	"syscall"
	"time"

	"github.com/goastian/midorivpn-agent/internal/caps"
	"github.com/goastian/midorivpn-agent/internal/dns"
	"github.com/goastian/midorivpn-agent/internal/rpc"
	"github.com/goastian/midorivpn-agent/internal/state"
)

var errAlreadyRunning = errors.New("agent already running")

func ensureBrowserToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(raw)
	path, err := writeRuntimeFile("midorivpn-agent.token", []byte(token+"\n"))
	return token, path, err
}

func openBrowserUI(port int, token string) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/#/?agent_token=%s", port, token)
	body := "<!doctype html><meta name=referrer content=no-referrer><meta http-equiv=refresh content=\"0;url=" + html.EscapeString(url) + "\"><title>MidoriVPN</title>"
	launchPath, err := writeRuntimeFile("midorivpn-launch.html", []byte(body))
	if err != nil {
		return fmt.Errorf("write browser launch file: %w", err)
	}
	if err := exec.Command("/usr/bin/xdg-open", launchPath).Start(); err != nil {
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
	token, err := readRuntimeToken()
	if err != nil {
		return fmt.Errorf("read running agent token: %w", err)
	}
	return openBrowserUI(port, token)
}

func main() {
	// Refuse legacy broad grants before reading caller paths or starting any
	// child. Reinstall/re-authorize the minimal network-only capability set.
	if err := caps.ValidateProcessPrivileges(); err != nil {
		slog.Error("unsafe agent privileges", "error", err)
		os.Exit(1)
	}
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		slog.Error("cannot initialize safe tool path", "error", err)
		os.Exit(1)
	}
	port := flag.Int("port", 7071, "local RPC server port")
	logLevel := flag.String("log", "info", "log level: debug|info|warn|error")
	uiDir := flag.String("ui-dir", "", "directory containing the compiled local browser UI")
	openUI := flag.Bool("open-ui", false, "open the local UI in the system browser")
	background := flag.Bool("background", false, "start without opening the browser UI")
	autostart := flag.Bool("autostart", false, "start in background from an XDG autostart entry")
	resumeSession := flag.Bool("resume-session", false, "reuse the protected RPC session after an agent restart")
	parentPID := flag.Int("parent-pid", 0, "desktop shell PID to supervise after capability exec")
	flag.Parse()
	if *parentPID != 0 {
		if err := superviseParent(*parentPID); err != nil {
			slog.Error("desktop parent unavailable", "error", err)
			os.Exit(1)
		}
	}

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

	var browserToken, browserTokenFile string
	if *resumeSession {
		browserToken, err = readRuntimeToken()
		browserTokenFile = filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "midorivpn-agent.token")
	} else {
		browserToken, browserTokenFile, err = ensureBrowserToken()
	}
	if err != nil {
		slog.Error("cannot initialize browser UI session", "err", err)
		os.Exit(1)
	}
	defer os.Remove(browserTokenFile)

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

	// Initialize auth concurrently so a slow IdP does not block the local UI.
	go func() {
		initCtx, initCancel := context.WithTimeout(ctx, 20*time.Second)
		if err := srv.Init(initCtx); err != nil {
			slog.Warn("agent init reported an error; continuing", "err", err)
		}
		initCancel()
	}()

	if *openUI && !*background && !*autostart {
		go waitAndOpenBrowser(ctx, *port, browserToken)
	}

	if err := srv.Start(ctx, browserToken); err != nil {
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
