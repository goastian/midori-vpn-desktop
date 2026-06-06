use crate::agent::{lock_safe, AgentToken};
use reqwest::Client;
use reqwest::RequestBuilder;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use tauri::{AppHandle, Manager};

const AGENT_BASE: &str = "http://127.0.0.1:7071";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY_MS: u64 = 300;

/// Shared reqwest client — avoids creating a new TCP connection pool per call.
fn http_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("failed to build HTTP client")
    })
}

fn read_token(app: &AppHandle) -> String {
    lock_safe(&app.state::<AgentToken>().0).clone()
}

#[derive(Copy, Clone)]
enum AgentMethod {
    Get,
    Post,
    Delete,
}

fn is_allowed_agent_path(method: AgentMethod, path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.contains("..")
        || path.contains("://")
    {
        return false;
    }

    matches!(
        (method, path),
        (AgentMethod::Get, "status")
            | (AgentMethod::Get, "servers")
            | (AgentMethod::Get, "settings")
            | (AgentMethod::Get, "mesh/exit-nodes")
            | (AgentMethod::Get, "public-ip")
            | (AgentMethod::Post, "auth/set-tokens")
            | (AgentMethod::Post, "auth/refresh")
            | (AgentMethod::Post, "vpn/connect")
            | (AgentMethod::Post, "vpn/disconnect")
            | (AgentMethod::Post, "mesh/enable")
            | (AgentMethod::Post, "mesh/disable")
            | (AgentMethod::Post, "mesh/exit-node")
            | (AgentMethod::Post, "mesh/full-tunnel/enable")
            | (AgentMethod::Post, "mesh/full-tunnel/disable")
            | (AgentMethod::Post, "oauth/start")
            | (AgentMethod::Post, "settings")
            | (AgentMethod::Delete, "auth/logout")
            | (AgentMethod::Delete, "mesh/exit-node")
    )
}

async fn read_json_response(resp: reqwest::Response) -> Result<Value, String> {
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;

    if !status.is_success() {
        return Err(classify_http_error(status, &body));
    }

    serde_json::from_str(&body).map_err(|e| e.to_string())
}

fn classify_http_error(status: reqwest::StatusCode, body: &str) -> String {
    if status == reqwest::StatusCode::FORBIDDEN && body.contains("origin not allowed") {
        return format!("auth_origin_rejected: {} {}", status, body);
    }
    // Mark auth failures with a stable prefix so the frontend can
    // distinguish them from generic agent errors.
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return format!("auth_expired: {} {}", status, body);
    }
    if body.is_empty() {
        status.to_string()
    } else {
        format!("{}: {}", status, body)
    }
}

/// Send a request using the given closure. On transient network errors
/// (connect/timeout) retries once after a short delay. HTTP-level errors
/// (4xx/5xx) are NOT retried — they bubble through `read_json_response`.
async fn send_with_retry<F, Fut>(f: F) -> Result<reqwest::Response, reqwest::Error>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    match f().await {
        Ok(r) => Ok(r),
        Err(e) if e.is_connect() || e.is_timeout() => {
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            f().await
        }
        Err(e) => Err(e),
    }
}

pub async fn post(app: &AppHandle, path: &str, body: &str) -> Result<Value, String> {
    request(app, AgentMethod::Post, path, |client, url, token| {
        client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Agent-Token", token)
            .body(body.to_string())
    })
    .await
}

pub async fn get(app: &AppHandle, path: &str) -> Result<Value, String> {
    request(app, AgentMethod::Get, path, |client, url, token| {
        client.get(url).header("X-Agent-Token", token)
    })
    .await
}

pub async fn delete(app: &AppHandle, path: &str) -> Result<Value, String> {
    request(app, AgentMethod::Delete, path, |client, url, token| {
        client.delete(url).header("X-Agent-Token", token)
    })
    .await
}

async fn request<F>(
    app: &AppHandle,
    method: AgentMethod,
    path: &str,
    build: F,
) -> Result<Value, String>
where
    F: Fn(&Client, &str, &str) -> RequestBuilder,
{
    if !is_allowed_agent_path(method, path) {
        return Err("agent path is not allowed".to_string());
    }

    let token = read_token(app);
    let client = http_client();
    let url = format!("{}/{}", AGENT_BASE, path);
    let mut resp = send_with_retry(|| build(client, &url, &token).send())
        .await
        .map_err(|e| e.to_string())?;

    // If the agent just restarted, the in-memory token can rotate between the
    // first read and the request dispatch. Retry once with the latest token.
    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        let latest = read_token(app);
        if !latest.is_empty() && latest != token {
            resp = send_with_retry(|| build(client, &url, &latest).send())
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    read_json_response(resp).await
}

#[cfg(test)]
mod tests {
    use super::{classify_http_error, is_allowed_agent_path, AgentMethod};

    #[test]
    fn allows_only_known_agent_routes() {
        assert!(is_allowed_agent_path(AgentMethod::Get, "status"));
        assert!(is_allowed_agent_path(AgentMethod::Post, "vpn/connect"));
        assert!(is_allowed_agent_path(AgentMethod::Delete, "mesh/exit-node"));

        assert!(!is_allowed_agent_path(AgentMethod::Get, "/status"));
        assert!(!is_allowed_agent_path(
            AgentMethod::Get,
            "http://127.0.0.1:7071/status"
        ));
        assert!(!is_allowed_agent_path(AgentMethod::Get, "status?token=x"));
        assert!(!is_allowed_agent_path(AgentMethod::Get, "../status"));
        assert!(!is_allowed_agent_path(AgentMethod::Post, "servers"));
        assert!(!is_allowed_agent_path(AgentMethod::Delete, "settings"));
    }

    #[test]
    fn classifies_origin_rejected_separately_from_expired_auth() {
        let msg = classify_http_error(
            reqwest::StatusCode::FORBIDDEN,
            "{\"ok\":false,\"error\":\"origin not allowed\"}",
        );

        assert!(msg.starts_with("auth_origin_rejected: 403 Forbidden"));
        assert!(!msg.starts_with("auth_expired:"));
    }
}
