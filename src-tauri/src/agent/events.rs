use tauri::{AppHandle, Emitter, Manager};

use super::process::is_agent_healthy;
use super::token::{lock_safe, AgentSupervisorStop, AgentToken};

#[derive(Clone, serde::Serialize)]
pub struct AgentStatusPayload {
    pub status: String, // "running" | "restarting" | "failed"
}

pub(super) fn emit_agent_status(app: &AppHandle, status: &str) {
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

            // Poll for agent readiness with short interval (~100ms) instead of
            // a fixed 1s sleep. During restart the supervisor swaps the process
            // quickly; reconnecting fast minimises the window where SSE events
            // (e.g. mesh_status from auto-enable) can be missed.
            for _ in 0..30 {
                if supervisor_should_stop(&app) {
                    return;
                }
                if is_agent_healthy(port) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    });
}

pub(super) fn supervisor_should_stop(app: &AppHandle) -> bool {
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
