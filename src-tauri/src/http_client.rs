use reqwest::Client;
use serde_json::Value;
use tauri::AppHandle;

const AGENT_BASE: &str = "http://127.0.0.1:7071";

pub async fn post(app: &AppHandle, path: &str, body: &str) -> Result<Value, String> {
    let _ = app; // future: read port from config
    let client = Client::new();
    let url = format!("{}/{}", AGENT_BASE, path);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().await.map_err(|e| e.to_string())
}

pub async fn get(app: &AppHandle, path: &str) -> Result<Value, String> {
    let _ = app;
    let client = Client::new();
    let url = format!("{}/{}", AGENT_BASE, path);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().await.map_err(|e| e.to_string())
}

pub async fn delete(app: &AppHandle, path: &str) -> Result<Value, String> {
    let _ = app;
    let client = Client::new();
    let url = format!("{}/{}", AGENT_BASE, path);
    let resp = client
        .delete(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().await.map_err(|e| e.to_string())
}
