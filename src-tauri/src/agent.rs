use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

pub struct AgentProcess(pub Mutex<Option<Child>>);

/// Spawn the bundled agent sidecar
pub fn start_agent(app: &AppHandle, port: u16) -> std::io::Result<()> {
    let state = app.state::<AgentProcess>();
    let mut guard = state.0.lock().unwrap();
    if guard.is_some() {
        return Ok(()); // already running
    }

    let agent_path = app
        .path()
        .resource_dir()
        .unwrap()
        .join("agent");

    let child = Command::new(agent_path)
        .arg("--port")
        .arg(port.to_string())
        .spawn()?;

    *guard = Some(child);
    Ok(())
}

/// Kill the agent process
pub fn stop_agent(app: &AppHandle) {
    let state = app.state::<AgentProcess>();
    let mut guard = state.0.lock().unwrap();
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
    }
}
