//! security.rs — detects SELinux, AppArmor, firewalld/ufw at startup and
//! returns actionable warnings so the Vue frontend can display them.

use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct SecurityIssue {
    /// Short machine-readable key (e.g. "selinux_enforcing")
    pub id: String,
    /// One-line human title
    pub title: String,
    /// Full explanation shown in the banner
    pub detail: String,
    /// Single command (with && if multi-step) the user can copy and run to fix the issue.
    /// Empty string if there is no automated fix.
    pub fix_cmd: String,
    /// "error" | "warning" | "info"
    pub level: String,
}

/// Run all security checks and return any issues found.
pub fn check() -> Vec<SecurityIssue> {
    let mut issues: Vec<SecurityIssue> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        check_selinux(&mut issues);
        check_apparmor(&mut issues);
        check_firewall(&mut issues);
    }

    issues
}

// ─── SELinux ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn check_selinux(issues: &mut Vec<SecurityIssue>) {
    // /sys/fs/selinux/enforce: "1" = enforcing, "0" = permissive, missing = disabled
    let enforcing = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    if !enforcing {
        return;
    }

    // Check if the agent binary already has an executable context (bin_t / usr_t).
    // `ls -Z <path>` outputs the context; we look for a non-lib_t type.
    let context_ok = std::process::Command::new("ls")
        .args(["-Z", "/usr/local/bin/midorivpn-agent"])
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            // bin_t, usr_t, usr_local_t are all fine; lib_t is not
            !out.contains("lib_t")
                && (out.contains("bin_t") || out.contains("usr_t") || out.contains("usr_local_t"))
        })
        .unwrap_or(false);

    if !context_ok {
        issues.push(SecurityIssue {
            id: "selinux_wrong_context".into(),
            title: "SELinux: agent binary has wrong file context".into(),
            detail: concat!(
                "SELinux is enforcing and /usr/local/bin/midorivpn-agent has a context that ",
                "prevents it from running (likely lib_t).\n\n",
                "Run the fix command below to restore the correct bin_t context."
            ).into(),
            fix_cmd: "sudo restorecon -v /usr/local/bin/midorivpn-agent || sudo chcon -t bin_t /usr/local/bin/midorivpn-agent".into(),
            level: "error".into(),
        });
    }
}

// ─── AppArmor ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn check_apparmor(issues: &mut Vec<SecurityIssue>) {
    let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|s| s.trim() == "Y")
        .unwrap_or(false);

    if !enabled {
        return;
    }

    // Check if there is a profile for the agent binary in enforce mode.
    let profile_enforced = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles")
        .map(|s| s.contains("midorivpn") && s.contains("(enforce)"))
        .unwrap_or(false);

    if profile_enforced {
        issues.push(SecurityIssue {
            id: "apparmor_enforced".into(),
            title: "AppArmor: MidoriVPN profile is in enforce mode".into(),
            detail: "An AppArmor profile for MidoriVPN is active and may block the agent. Run the fix command to put it in complain mode.".into(),
            fix_cmd: "sudo aa-complain /usr/local/bin/midorivpn-agent".into(),
            level: "warning".into(),
        });
    }
}

// ─── Firewall ─────────────────────────────────────────────────────────────────
// Firewall rules (firewalld/ufw port 51820, nftables) are applied automatically
// by the agent through the permissions consent flow. No startup warning is shown;
// instead the permissions modal guides the user through granting consent once.

#[cfg(target_os = "linux")]
fn check_firewall(_issues: &mut Vec<SecurityIssue>) {
    // Intentionally empty: firewall configuration is handled by the
    // permissions consent modal in the UI, not as a startup security warning.
}
