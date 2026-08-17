mod events;
mod permissions;
mod process;
mod supervisor;
mod token;

pub use events::start_event_relay;
pub use process::{restart_agent, start_agent, stop_agent};
pub use supervisor::start_supervisor;
pub use token::{AgentProcess, AgentSupervisorStop, AgentToken};

pub(crate) use token::lock_safe;

/// Returns true if the agent binary has the complete capability set needed by
/// the desktop system-wide tunnel, including DNS protection on resolvconf
/// hosts.
#[tauri::command]
pub fn agent_has_caps() -> bool {
    permissions::agent_has_caps()
}

/// Attempts to grant the agent binary all Linux capabilities required by the
/// desktop system-wide tunnel via `pkexec setcap`.
#[tauri::command]
pub fn grant_agent_permissions() -> bool {
    permissions::grant_agent_permissions()
}

/// Grants the extended cap set required by the resolvconf DNS backend
/// (adds CAP_DAC_OVERRIDE + CAP_LINUX_IMMUTABLE).
#[tauri::command]
pub fn grant_dns_protection_caps() -> bool {
    permissions::grant_dns_protection_caps()
}

/// Revokes all capabilities from the agent binary via `pkexec setcap -r`.
#[tauri::command]
pub fn revert_agent_permissions() -> bool {
    permissions::revert_agent_permissions()
}
