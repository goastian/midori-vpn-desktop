use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use tauri::{AppHandle, Emitter, Manager};

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
fn generate_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Installed path of the agent binary.
/// Must match the `exec.path` annotation in the polkit policy.
/// Path must be under /usr/local/bin/ so SELinux assigns bin_t context,
/// allowing pkexec to use it as an entrypoint.
const AGENT_INSTALLED_PATH: &str = "/usr/local/bin/midorivpn-agent";

fn agent_command_path(app: &AppHandle) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let _ = app;
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

fn is_agent_healthy(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250)).is_ok()
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

/// One-shot install of CAP_NET_ADMIN/CAP_NET_RAW on the agent binary.
///
/// Runs `pkexec setcap cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep <agent>`. On success
/// the agent can be launched directly forever after, no further pkexec
/// prompts. Returns true only if the resulting binary actually carries the
/// caps (so we don't loop on a silent failure).
#[cfg(target_os = "linux")]
fn try_install_caps() -> bool {
    let Some(setcap) = find_setcap_path() else {
        return false;
    };

    let status = Command::new("pkexec")
        .arg(setcap)
        .arg("cap_net_admin,cap_net_raw,cap_dac_override,cap_linux_immutable=ep")
        .arg(AGENT_INSTALLED_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    matches!(status, Ok(s) if s.success()) && agent_has_net_admin_cap()
}

#[cfg(not(target_os = "linux"))]
fn try_install_caps() -> bool {
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
#[tauri::command]
pub fn agent_has_caps() -> bool {
    #[cfg(target_os = "linux")]
    return agent_has_net_admin_cap();
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Attempts to grant the agent binary the required Linux capabilities via
/// `pkexec setcap`.  Returns true on success (caps are now set).
#[tauri::command]
pub fn grant_agent_permissions() -> bool {
    #[cfg(target_os = "linux")]
    return try_install_caps();
    #[cfg(not(target_os = "linux"))]
    return true;
}

/// Revokes all capabilities from the agent binary via `pkexec setcap -r`.
/// This is the symmetric counterpart to `grant_agent_permissions` and is
/// called on app exit (and via the explicit "Revertir permisos" button).
/// Returns true on success; false if the user cancelled polkit or setcap failed.
#[tauri::command]
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
        // SIGTERM — let Go run deferred Shutdown() cleanup (15 s budget).
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

// ── Agent supervisor ──────────────────────────────────────────────────────────

#[derive(Clone, serde::Serialize)]
pub struct AgentStatusPayload {
    pub status: String, // "running" | "restarting" | "failed"
}

fn emit_agent_status(app: &AppHandle, status: &str) {
    let _ = app.emit(
        "agent://status",
        AgentStatusPayload {
            status: status.to_string(),
        },
    );
}

#[derive(Clone, serde::Serialize)]
pub struct AgentEventPayload {
    pub event: String,
    pub data: serde_json::Value,
}

/// Starts a single Rust-owned SSE relay. The WebView receives sanitized Tauri
/// events and never receives the MIDORIVPN_AGENT_TOKEN needed by the local RPC.
pub fn start_event_relay(app: AppHandle, port: u16) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(1))
            .build()
            .expect("failed to build agent event relay client");
        let url = format!("http://127.0.0.1:{port}/events");

        loop {
            if supervisor_should_stop(&app) {
                return;
            }

            let token = lock_safe(&app.state::<AgentToken>().0).clone();
            if token.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }

            if let Err(err) = relay_agent_events_once(&app, &client, &url, &token).await {
                eprintln!("[midorivpn] agent event relay reconnecting: {err}");
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

fn supervisor_should_stop(app: &AppHandle) -> bool {
    app.try_state::<AgentSupervisorStop>()
        .map(|state| state.0.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(false)
}

async fn relay_agent_events_once(
    app: &AppHandle,
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<(), String> {
    let mut resp = client
        .get(url)
        .header("Accept", "text/event-stream")
        .header("X-Agent-Token", token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("agent events HTTP {}", resp.status()));
    }

    let mut buffer = String::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if supervisor_should_stop(app) {
            return Ok(());
        }
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buffer.find("\n\n") {
            let block = buffer[..pos].to_string();
            buffer.drain(..pos + 2);
            emit_agent_event_block(app, &block);
        }
    }

    Ok(())
}

fn emit_agent_event_block(app: &AppHandle, block: &str) {
    let mut event = "message";
    let mut data = String::new();

    for raw_line in block.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event = rest.trim();
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        }
    }

    if data.is_empty() {
        return;
    }

    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(data) => {
            let _ = app.emit(
                "agent://event",
                AgentEventPayload {
                    event: event.to_string(),
                    data,
                },
            );
        }
        Err(err) => eprintln!("[midorivpn] dropped malformed agent event: {err}"),
    }
}

fn open_agent_log_file() -> std::fs::File {
    let log_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let log_path = log_dir.join("midorivpn-agent.log");
    rotate_agent_log(&log_path);
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .unwrap_or_else(|_| std::fs::File::open("/dev/null").unwrap())
}

fn rotate_agent_log(path: &std::path::Path) {
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
/// child — caller is responsible for updating `AgentProcess`.
fn spawn_and_wait(app: &AppHandle, port: u16) -> std::io::Result<Child> {
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

/// Start the agent supervisor in a background thread. The supervisor:
///   - Spawns the agent and monitors its health every 5 s.
///   - On 3 consecutive health-check failures, kills the dead process and
///     restarts with exponential backoff (1 s → 2 s → 4 s … ≤ 30 s).
///   - Resets the failure counter after 5 minutes without a crash.
///   - Emits `agent://status` events ("running", "restarting", "failed")
///     so the frontend can show an appropriate banner.
///   - Stops cleanly when `AgentSupervisorStop` is set to true.
pub fn start_supervisor(app: AppHandle, port: u16) {
    let stop = app.state::<AgentSupervisorStop>().0.clone();

    std::thread::Builder::new()
        .name("agent-supervisor".to_string())
        .spawn(move || {
            const MAX_RESTARTS_IN_WINDOW: u32 = 5;
            const WINDOW_SECS: u64 = 300; // 5 min
            const HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
            const HEALTH_FAIL_THRESHOLD: u32 = 3;

            let mut restarts_in_window = 0u32;
            let mut window_start = std::time::Instant::now();

            loop {
                // ── Spawn / restart the agent ─────────────────────────────
                if restarts_in_window > 0 {
                    // Reset window counter after 5 minutes.
                    if window_start.elapsed().as_secs() >= WINDOW_SECS {
                        restarts_in_window = 0;
                        window_start = std::time::Instant::now();
                    }

                    if restarts_in_window >= MAX_RESTARTS_IN_WINDOW {
                        emit_agent_status(&app, "failed");
                        eprintln!("[supervisor] agent failed {restarts_in_window} times; giving up");
                        break;
                    }

                    let backoff_secs = (1u64 << restarts_in_window.min(5)).min(30);
                    emit_agent_status(&app, "restarting");
                    eprintln!("[supervisor] restarting agent in {backoff_secs}s (attempt {restarts_in_window})");
                    std::thread::sleep(std::time::Duration::from_secs(backoff_secs));
                }

                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match spawn_and_wait(&app, port) {
                    Ok(child) => {
                        {
                            let state = app.state::<AgentProcess>();
                            *lock_safe(&state.0) = Some(child);
                        }
                        emit_agent_status(&app, "running");
                        eprintln!("[supervisor] agent running on port {port}");
                    }
                    Err(e) => {
                        eprintln!("[supervisor] failed to spawn agent: {e}");
                        restarts_in_window += 1;
                        continue;
                    }
                }

                // ── Health-monitoring inner loop ──────────────────────────
                let mut consecutive_failures = 0u32;
                loop {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return; // clean exit requested
                    }

                    std::thread::sleep(HEALTH_INTERVAL);

                    if is_agent_healthy(port) {
                        consecutive_failures = 0;
                    } else {
                        consecutive_failures += 1;
                        eprintln!("[supervisor] health-check failed ({consecutive_failures}/{HEALTH_FAIL_THRESHOLD})");
                        if consecutive_failures >= HEALTH_FAIL_THRESHOLD {
                            // Kill the stale process and let the outer loop restart.
                            let state = app.state::<AgentProcess>();
                            if let Some(mut child) = lock_safe(&state.0).take() {
                                let _ = child.kill();
                                let _ = child.wait();
                            }
                            restarts_in_window += 1;
                            break; // break inner loop → restart
                        }
                    }
                }
            }
        })
        .expect("failed to spawn agent supervisor thread");
}
