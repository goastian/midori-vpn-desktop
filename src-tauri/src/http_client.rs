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

async fn read_json_response(resp: reqwest::Response) -> Result<Value, String> {
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;

    if !status.is_success() {
        // Mark auth failures with a stable prefix so the frontend can
        // distinguish them from generic agent errors.
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(format!("auth_expired: {} {}", status, body));
        }
        let message = if body.is_empty() {
            status.to_string()
        } else {
            format!("{}: {}", status, body)
        };
        return Err(message);
    }

    serde_json::from_str(&body).map_err(|e| e.to_string())
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
    request(app, path, |client, url, token| {
        client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Agent-Token", token)
            .body(body.to_string())
    })
    .await
}

pub async fn get(app: &AppHandle, path: &str) -> Result<Value, String> {
    request(app, path, |client, url, token| {
        client.get(url).header("X-Agent-Token", token)
    })
    .await
}

pub async fn delete(app: &AppHandle, path: &str) -> Result<Value, String> {
    request(app, path, |client, url, token| {
        client.delete(url).header("X-Agent-Token", token)
    })
    .await
}

async fn request<F>(app: &AppHandle, path: &str, build: F) -> Result<Value, String>
where
    F: Fn(&Client, &str, &str) -> RequestBuilder,
{
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
