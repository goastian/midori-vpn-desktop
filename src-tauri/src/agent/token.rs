use std::io;
use std::process::Child;
use std::sync::{Arc, Mutex, MutexGuard};

/// Acquire a Mutex lock recovering automatically from a poisoned mutex.
/// We use this instead of `.lock().unwrap()` so a panic in one thread doesn't
/// take down the whole supervisor.
pub(crate) fn lock_safe<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

pub struct AgentProcess(pub Mutex<Option<Child>>);

/// Shared flag used to signal the supervisor loop to stop (e.g. on app exit).
pub struct AgentSupervisorStop(pub Arc<std::sync::atomic::AtomicBool>);

/// Shared ephemeral token used to authenticate requests to the agent RPC.
/// Generated fresh on each `start_agent` call and passed only to trusted Rust
/// code plus the agent process via MIDORIVPN_AGENT_TOKEN.
pub struct AgentToken(pub Mutex<String>);

/// Generate a cryptographically random 32-byte hex token.
pub(super) fn generate_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}
