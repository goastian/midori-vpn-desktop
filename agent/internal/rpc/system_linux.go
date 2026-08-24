//go:build linux

package rpc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type securityIssue struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	FixCmd string `json:"fix_cmd"`
	Level  string `json:"level"`
}

func currentExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func findExecutable(candidates ...string) (string, error) {
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("required executable not installed")
}

func installedCapabilitiesGranted() bool {
	getcap, err := findExecutable("/usr/sbin/getcap", "/sbin/getcap", "/usr/bin/getcap", "/bin/getcap")
	if err != nil {
		return false
	}
	target, err := currentExecutable()
	if err != nil {
		return false
	}
	out, err := exec.Command(getcap, target).Output()
	if err != nil {
		return false
	}
	text := string(out)
	for _, capability := range []string{"cap_net_admin", "cap_net_raw", "cap_dac_override", "cap_linux_immutable"} {
		if !strings.Contains(text, capability) {
			return false
		}
	}
	return true
}

func setInstalledCapabilities(_ bool) (bool, error) {
	setcap, err := findExecutable("/usr/sbin/setcap", "/sbin/setcap", "/usr/bin/setcap", "/bin/setcap")
	if err != nil {
		return false, err
	}
	pkexec, err := findExecutable("/usr/bin/pkexec", "/bin/pkexec")
	if err != nil {
		return false, err
	}
	target, err := currentExecutable()
	if err != nil {
		return false, err
	}
	capabilitySet := "cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep"
	cmd := exec.Command(pkexec, setcap, capabilitySet, target)
	if output, runErr := cmd.CombinedOutput(); runErr != nil {
		return false, fmt.Errorf("set capabilities: %w: %s", runErr, strings.TrimSpace(string(output)))
	}
	return installedCapabilitiesGranted(), nil
}

func revokeInstalledCapabilities() (bool, error) {
	setcap, err := findExecutable("/usr/sbin/setcap", "/sbin/setcap", "/usr/bin/setcap", "/bin/setcap")
	if err != nil {
		return false, err
	}
	pkexec, err := findExecutable("/usr/bin/pkexec", "/bin/pkexec")
	if err != nil {
		return false, err
	}
	target, err := currentExecutable()
	if err != nil {
		return false, err
	}
	cmd := exec.Command(pkexec, setcap, "-r", target)
	if output, runErr := cmd.CombinedOutput(); runErr != nil {
		return false, fmt.Errorf("revoke capabilities: %w: %s", runErr, strings.TrimSpace(string(output)))
	}
	return !installedCapabilitiesGranted(), nil
}

func autostartPath() (string, error) {
	configHome := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "autostart", "midorivpn.desktop"), nil
}

func autostartEnabled() bool {
	path, err := autostartPath()
	if err != nil {
		return false
	}
	body, err := os.ReadFile(path)
	return err == nil && !strings.Contains(strings.ToLower(string(body)), "hidden=true") && !strings.Contains(strings.ToLower(string(body)), "x-gnome-autostart-enabled=false")
}

func quoteDesktopArg(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("desktop argument contains a newline")
	}
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "`", "\\`", "$", "\\$")
	return "\"" + replacer.Replace(value) + "\"", nil
}

func setAutostart(enabled bool, port int, uiDir string) error {
	path, err := autostartPath()
	if err != nil {
		return err
	}
	if !enabled {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	executable, err := currentExecutable()
	if err != nil {
		return err
	}
	execArg, err := quoteDesktopArg(executable)
	if err != nil {
		return err
	}
	uiArg, err := quoteDesktopArg(uiDir)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=MidoriVPN\nComment=Start MidoriVPN at login\nExec=%s --port %d --ui-dir %s --background\nIcon=midorivpn\nTerminal=false\nCategories=Network;Security;\nStartupNotify=false\nX-GNOME-Autostart-enabled=true\nX-MidoriVPN-Managed=true\n", execArg, port, uiArg)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func inspectSystemSecurity() []securityIssue {
	issues := make([]securityIssue, 0)
	if !installedCapabilitiesGranted() {
		issues = append(issues, securityIssue{ID: "network_capabilities_missing", Title: "Network permissions are not enabled", Detail: "Authorize MidoriVPN before creating a VPN interface.", Level: "warning"})
	}
	return issues
}
