use tauri::{AppHandle, Manager};

use super::events::emit_agent_status;
use super::process::{is_agent_healthy, spawn_and_wait};
use super::token::{lock_safe, AgentProcess, AgentSupervisorStop};

/// Start the agent supervisor in a background thread. The supervisor:
///   - Spawns the agent and monitors its health every 5 s.
///   - On 3 consecutive health-check failures, kills the dead process and
///     restarts with exponential backoff (1 s -> 2 s -> 4 s ... <= 30 s).
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
                // Spawn / restart the agent.
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
                    eprintln!(
                        "[supervisor] restarting agent in {backoff_secs}s (attempt {restarts_in_window})"
                    );
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

                // Health-monitoring inner loop.
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
                        eprintln!(
                            "[supervisor] health-check failed ({consecutive_failures}/{HEALTH_FAIL_THRESHOLD})"
                        );
                        if consecutive_failures >= HEALTH_FAIL_THRESHOLD {
                            // Kill the stale process and let the outer loop restart.
                            let state = app.state::<AgentProcess>();
                            if let Some(mut child) = lock_safe(&state.0).take() {
                                let _ = child.kill();
                                let _ = child.wait();
                            }
                            restarts_in_window += 1;
                            break; // break inner loop, restart
                        }
                    }
                }
            }
        })
        .expect("failed to spawn agent supervisor thread");
}
