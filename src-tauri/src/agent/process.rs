use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use tauri::{AppHandle, Manager};

use super::events::emit_agent_status;
use super::permissions::agent_command_path;
use super::token::{generate_token, lock_safe, AgentProcess, AgentSupervisorStop, AgentToken};

pub(super) fn is_agent_healthy(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250)).is_ok()
}

/// Kill any process currently listening on `port` that was not started by this
/// Tauri session. Used to evict a stale agent from a previous session so we
/// can start a fresh one with a newly-generated MIDORIVPN_AGENT_TOKEN.
///
/// On Linux we use `fuser -k PORT/tcp` which sends SIGKILL to the owner PID.
/// macOS and Windows use platform process tools against the packaged agent
/// name as a best-effort fallback.
/// Both failures are treated as non-fatal (we proceed and let spawn fail or
/// succeed on its own).
fn kill_stale_agent(port: u16) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("fuser")
            .arg("-k")
            .arg(format!("{}/tcp", port))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("pkill")
            .arg("-x")
            .arg("agent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", "agent.exe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    // Give the OS a moment to release the port before we try to bind it.
    std::thread::sleep(std::time::Duration::from_millis(200));
}

pub fn start_agent(app: &AppHandle, port: u16) -> std::io::Result<()> {
    let state = app.state::<AgentProcess>();
    let mut guard = lock_safe(&state.0);
    if guard.is_some() {
        return Ok(()); // already running
    }

    *guard = Some(spawn_and_wait(app, port)?);
    Ok(())
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        // SIGTERM: let Go run deferred Shutdown() cleanup (15 s budget).
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        unsafe {
            kill(child.id() as i32, 15);
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    // Fallback: SIGKILL
    let _ = child.kill();
    let _ = child.wait();
}

/// Restart the current agent process while keeping the supervisor enabled.
/// Useful after granting capabilities so the fresh process picks up file caps.
#[tauri::command]
pub fn restart_agent(app: AppHandle, port: u16) -> Result<(), String> {
    // Debounce: reject calls spaced less than 500ms apart to coalesce
    // accidental double-invocations (e.g. multiple components reacting to the
    // same caps grant). Without this, a quick succession of restart_agent
    // calls cycles the agent process needlessly and disrupts SSE/auto-mesh.
    static LAST_RESTART: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    {
        let cell = LAST_RESTART.get_or_init(|| Mutex::new(None));
        let mut guard = lock_safe(cell);
        let now = Instant::now();
        if let Some(prev) = *guard {
            if now.duration_since(prev) < std::time::Duration::from_millis(500) {
                return Ok(());
            }
        }
        *guard = Some(now);
    }

    let state = app.state::<AgentProcess>();
    let mut guard = lock_safe(&state.0);

    if let Some(mut child) = guard.take() {
        terminate_child(&mut child);
    }

    *guard = Some(spawn_and_wait(&app, port).map_err(|e| e.to_string())?);
    emit_agent_status(&app, "running");
    Ok(())
}

/// Stop the agent process gracefully.
/// Sends SIGTERM and waits up to 15 s for clean exit so the agent can
/// run its Shutdown() cleanup (revert nft tables, firewall rules, ip_forward,
/// resolv.conf). Falls back to SIGKILL after the deadline.
pub fn stop_agent(app: &AppHandle) {
    // Signal the supervisor loop to stop before killing the process so it
    // doesn't immediately restart the agent we're about to kill.
    if let Some(state) = app.try_state::<AgentSupervisorStop>() {
        state.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let state = app.state::<AgentProcess>();
    let mut guard = lock_safe(&state.0);
    if let Some(mut child) = guard.take() {
        terminate_child(&mut child);
    }
}

fn open_agent_log_file() -> Stdio {
    let log_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let log_path = log_dir.join("midorivpn-agent.log");
    rotate_agent_log(&log_path);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(f) => Stdio::from(f),
        Err(e) => {
            eprintln!(
                "agent log open failed ({}): {e}; falling back to /dev/null",
                log_path.display()
            );
            Stdio::null()
        }
    }
}

fn rotate_agent_log(path: &Path) {
    const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() <= MAX_LOG_BYTES {
        return;
    }

    let rotated = path.with_extension("log.1");
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, rotated);
}

/// Spawn the agent process and wait for it to be healthy. Does not store the
/// child; caller is responsible for updating `AgentProcess`.
pub(super) fn spawn_and_wait(app: &AppHandle, port: u16) -> std::io::Result<Child> {
    if is_agent_healthy(port) {
        kill_stale_agent(port);
    }

    let token = generate_token()?;
    {
        let tok_state = app.state::<AgentToken>();
        *lock_safe(&tok_state.0) = token.clone();
    }

    let log_file = open_agent_log_file();

    let agent_path = agent_command_path(app)?;
    let mut child = Command::new(agent_path)
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file)
        .env("MIDORIVPN_AGENT_TOKEN", &token)
        .spawn()?;

    for _ in 0..50 {
        if is_agent_healthy(port) {
            return Ok(child);
        }
        if let Some(status) = child.try_wait()? {
            if is_agent_healthy(port) {
                return Ok(child);
            }
            eprintln!("[supervisor] agent exited early before becoming healthy: {status}");
            return Err(io::Error::other(format!("agent exited early: {status}")));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(child) // healthy enough after 5 s
}
