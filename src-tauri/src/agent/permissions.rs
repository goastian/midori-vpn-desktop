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

/// The capabilities required by the desktop's system-wide tunnel.
///
/// `cap_dac_override` and `cap_linux_immutable` are needed on hosts that use
/// the resolvconf DNS backend (notably a number of Linux Mint installs). We
/// grant this single, explicit set from the main consent flow so a package
/// upgrade cannot leave an older, minimal capability set behind and then fail
/// only after the user presses Connect.
const DESKTOP_CAPS: [&str; 4] = [
    "cap_net_admin",
    "cap_net_raw",
    "cap_dac_override",
    "cap_linux_immutable",
];

#[cfg(target_os = "linux")]
fn find_agent_installed_path() -> &'static str {
    if std::path::Path::new("/usr/local/bin/midorivpn-agent").exists() {
        "/usr/local/bin/midorivpn-agent"
    } else if std::path::Path::new("/usr/bin/midorivpn-agent").exists() {
        "/usr/bin/midorivpn-agent"
    } else {
        AGENT_INSTALLED_PATH
    }
}

/// Returns true if the agent binary has any network capability. This is used
/// solely when revoking permissions, including the minimal set used by older
/// versions of the desktop client.
#[cfg(target_os = "linux")]
fn agent_has_any_network_cap() -> bool {
    Command::new("getcap")
        .arg(find_agent_installed_path())
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

/// Returns true only when the installed binary carries the entire capability
/// set used by the desktop client. Checking only CAP_NET_ADMIN made upgrades
/// from the pre-DNS-protection client look healthy even though their agent
/// could not write /etc/resolv.conf on resolvconf hosts.
#[cfg(target_os = "linux")]
fn agent_has_required_caps() -> bool {
    Command::new("getcap")
        .arg(find_agent_installed_path())
        .output()
        .map(|out| has_required_caps(&String::from_utf8_lossy(&out.stdout)))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn agent_has_required_caps() -> bool {
    true
}

fn has_required_caps(getcap_output: &str) -> bool {
    DESKTOP_CAPS
        .iter()
        .all(|capability| getcap_output.contains(capability))
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

    let target_binary = find_agent_installed_path();

    let status = Command::new("pkexec")
        .arg(setcap)
        .arg(cap_set)
        .arg(target_binary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    matches!(status, Ok(s) if s.success())
        && if extended {
            agent_has_required_caps()
        } else {
            agent_has_any_network_cap()
        }
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
