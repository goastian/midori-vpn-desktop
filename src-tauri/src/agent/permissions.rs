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

        Ok(PathBuf::from(AGENT_INSTALLED_PATH))
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
fn agent_has_net_admin_cap() -> bool {
    Command::new("getcap")
        .arg(AGENT_INSTALLED_PATH)
        .output()
        .map(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains("cap_net_admin")
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn agent_has_net_admin_cap() -> bool {
    true
}

/// One-shot install of capabilities on the agent binary.
///
/// Two cap sets are supported:
///   * "minimal" (default): `cap_net_admin,cap_net_raw=ep`, enough to manage
///     the WireGuard interface and use the systemd-resolved DNS backend.
///   * "dns-protection": adds `cap_dac_override,cap_linux_immutable=ep` so the
///     agent's resolvconf DNS backend can rewrite /etc/resolv.conf and mark
///     it immutable. Only required on systems without systemd-resolved.
///
/// Returns true only if the resulting binary actually carries CAP_NET_ADMIN
/// so we don't loop on a silent failure.
#[cfg(target_os = "linux")]
fn try_install_caps(extended: bool) -> bool {
    let Some(setcap) = find_setcap_path() else {
        return false;
    };

    let cap_set = if extended {
        "cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep"
    } else {
        "cap_net_admin,cap_net_raw=ep"
    };

    let status = Command::new("pkexec")
        .arg(setcap)
        .arg(cap_set)
        .arg(AGENT_INSTALLED_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    matches!(status, Ok(s) if s.success()) && agent_has_net_admin_cap()
}

#[cfg(not(target_os = "linux"))]
fn try_install_caps(_extended: bool) -> bool {
    false
}

/// Find the `setcap` binary path on this system. Distros vary between
/// /sbin and /usr/sbin so we probe both.
#[cfg(target_os = "linux")]
fn find_setcap_path() -> Option<&'static str> {
    ["/sbin/setcap", "/usr/sbin/setcap"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

/// Returns true if the agent binary already has CAP_NET_ADMIN set.
pub fn agent_has_caps() -> bool {
    #[cfg(target_os = "linux")]
    return agent_has_net_admin_cap();
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Attempts to grant the agent binary the minimal Linux capabilities
/// (CAP_NET_ADMIN + CAP_NET_RAW) via `pkexec setcap`. Returns true on success.
pub fn grant_agent_permissions() -> bool {
    #[cfg(target_os = "linux")]
    return try_install_caps(false);
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
        if !agent_has_net_admin_cap() {
            return true;
        }

        let Some(setcap) = find_setcap_path() else {
            return false;
        };

        let status = Command::new("pkexec")
            .arg(setcap)
            .arg("-r")
            .arg(AGENT_INSTALLED_PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Verify caps were actually removed.
        matches!(status, Ok(s) if s.success()) && !agent_has_net_admin_cap()
    }
    #[cfg(not(target_os = "linux"))]
    return true;
}

// Capabilities are granted at runtime via pkexec setcap (see
// `try_install_caps`). The .deb postinst no longer applies them so users
// always go through the explicit consent dialog on first launch.
