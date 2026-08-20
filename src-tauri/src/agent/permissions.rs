use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use tauri::{AppHandle, Manager};

/// Installed path of the agent binary.
/// Must match the `exec.path` annotation in the polkit policy.
/// Path must be under /usr/local/bin/ so SELinux assigns bin_t context,
/// allowing pkexec to use it as an entrypoint.
pub(super) const AGENT_INSTALLED_PATH: &str = "/usr/local/bin/midorivpn-agent";

pub(super) fn agent_command_path(app: &AppHandle) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("APPIMAGE").is_some() {
            if let Ok(path) = app
                .path()
                .resolve("agent", tauri::path::BaseDirectory::Resource)
            {
                if path.exists() {
                    return Ok(path);
                }
            }
        }

        let target = find_agent_installed_path();
        Ok(PathBuf::from(target))
    }

    #[cfg(target_os = "windows")]
    {
        app.path()
            .resolve("agent.exe", tauri::path::BaseDirectory::Resource)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))
    }

    #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
    {
        app.path()
            .resolve("agent", tauri::path::BaseDirectory::Resource)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))
    }
}

#[cfg(target_os = "linux")]
fn find_agent_installed_path() -> &'static str {
    if std::path::Path::new("/usr/local/bin/midorivpn-agent").exists() {
        "/usr/local/bin/midorivpn-agent"
    } else if std::path::Path::new("/usr/bin/midorivpn-agent").exists() {
        "/usr/bin/midorivpn-agent"
    } else if std::path::Path::new("/usr/lib/MidoriVPN/agent").exists() {
        "/usr/lib/MidoriVPN/agent"
    } else if std::path::Path::new("/usr/lib/midorivpn/agent").exists() {
        "/usr/lib/midorivpn/agent"
    } else if std::path::Path::new("/usr/lib/midorivpn-desktop/agent").exists() {
        "/usr/lib/midorivpn-desktop/agent"
    } else {
        AGENT_INSTALLED_PATH
    }
}

/// Returns true if the agent binary has any network capability.
#[cfg(target_os = "linux")]
fn agent_has_any_network_cap() -> bool {
    let target = find_agent_installed_path();
    Command::new("getcap")
        .arg(target)
        .output()
        .map(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains("cap_net_admin")
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn agent_has_any_network_cap() -> bool {
    true
}

/// Returns true when the installed binary carries CAP_NET_ADMIN (the essential capability for WireGuard & TUN).
#[cfg(target_os = "linux")]
fn agent_has_required_caps() -> bool {
    agent_has_any_network_cap()
}

#[cfg(not(target_os = "linux"))]
fn agent_has_required_caps() -> bool {
    true
}

/// One-shot install of capabilities on the agent binary with automatic fallback and informative logging.
#[cfg(target_os = "linux")]
fn try_install_caps(extended: bool) -> bool {
    let Some(setcap) = find_setcap_path() else {
        eprintln!("[permissions] Error: setcap binary not found in standard paths (/usr/sbin, /sbin, /usr/bin, /bin)");
        return false;
    };

    let target_binary = find_agent_installed_path();
    eprintln!("[permissions] Attempting to grant capabilities to '{}' using setcap '{}' (extended={})", target_binary, setcap, extended);

    if extended {
        match Command::new("pkexec")
            .arg(setcap)
            .arg("cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep")
            .arg(target_binary)
            .output()
        {
            Ok(out) => {
                if out.status.success() {
                    eprintln!("[permissions] pkexec extended setcap succeeded");
                    if agent_has_required_caps() {
                        return true;
                    }
                } else {
                    let err = String::from_utf8_lossy(&out.stderr);
                    eprintln!("[permissions] pkexec extended setcap failed (exit code {:?}): {}", out.status.code(), err.trim());
                }
            }
            Err(e) => {
                eprintln!("[permissions] Error launching pkexec: {}", e);
            }
        }
    }

    eprintln!("[permissions] Applying standard capability set (cap_net_admin,cap_net_raw=ep) on '{}'", target_binary);
    match Command::new("pkexec")
        .arg(setcap)
        .arg("cap_net_admin,cap_net_raw=ep")
        .arg(target_binary)
        .output()
    {
        Ok(out) => {
            if out.status.success() {
                eprintln!("[permissions] pkexec standard setcap succeeded");
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                eprintln!("[permissions] pkexec standard setcap failed (exit code {:?}): {}", out.status.code(), err.trim());
            }
        }
        Err(e) => {
            eprintln!("[permissions] Error executing pkexec standard setcap: {}", e);
        }
    }

    let ok = agent_has_required_caps();
    eprintln!("[permissions] Verification result for '{}': {}", target_binary, if ok { "GRANTED (CAP_NET_ADMIN active)" } else { "NOT GRANTED" });
    ok
}

#[cfg(not(target_os = "linux"))]
fn try_install_caps(_extended: bool) -> bool {
    false
}

/// Find the `setcap` binary path on this system. Distros vary between
/// /sbin, /usr/sbin, /usr/bin, /bin so we probe all.
#[cfg(target_os = "linux")]
fn find_setcap_path() -> Option<&'static str> {
    [
        "/usr/sbin/setcap",
        "/sbin/setcap",
        "/usr/bin/setcap",
        "/bin/setcap",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
}

/// Returns true if the agent binary has all permissions required by the
/// desktop full-tunnel flow.
pub fn agent_has_caps() -> bool {
    #[cfg(target_os = "linux")]
    return agent_has_required_caps();
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Attempts to grant the agent binary the complete Linux capability set used
/// by the desktop full-tunnel flow. Returns true only after verification.
pub fn grant_agent_permissions() -> bool {
    #[cfg(target_os = "linux")]
    return try_install_caps(true);
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Grants the extended cap set required by the resolvconf DNS backend
/// (adds CAP_DAC_OVERRIDE + CAP_LINUX_IMMUTABLE). Only call this after the
/// agent reports `dns_backend = "resolvconf"` and `caps_ok = false`.
pub fn grant_dns_protection_caps() -> bool {
    #[cfg(target_os = "linux")]
    return try_install_caps(true);
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Revokes all capabilities from the agent binary via `pkexec setcap -r`.
/// This is the symmetric counterpart to `grant_agent_permissions` and is
/// called on app exit (and via the explicit "Revertir permisos" button).
/// Returns true on success; false if the user cancelled polkit or setcap failed.
pub fn revert_agent_permissions() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Nothing to revoke: avoid triggering an unnecessary polkit prompt.
        if !agent_has_any_network_cap() {
            return true;
        }

        let Some(setcap) = find_setcap_path() else {
            return false;
        };

        let status = Command::new("pkexec")
            .arg(setcap)
            .arg("-r")
            .arg(find_agent_installed_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Verify caps were actually removed.
        matches!(status, Ok(s) if s.success()) && !agent_has_any_network_cap()
    }
    #[cfg(not(target_os = "linux"))]
    return true;
}

// Capabilities are granted at runtime via pkexec setcap (see
// `try_install_caps`). The .deb postinst no longer applies them so users
// always go through the explicit consent dialog on first launch.

#[cfg(test)]
mod tests {
    use super::has_required_caps;

    #[test]
    fn required_caps_rejects_the_legacy_minimal_set() {
        let output = "/usr/local/bin/midorivpn-agent cap_net_admin,cap_net_raw=ep\n";
        assert!(!has_required_caps(output));
    }

    #[test]
    fn required_caps_accepts_the_desktop_set_in_any_order() {
        let output = "/usr/local/bin/midorivpn-agent cap_linux_immutable,cap_net_raw,cap_dac_override,cap_net_admin=ep\n";
        assert!(has_required_caps(output));
    }
}
