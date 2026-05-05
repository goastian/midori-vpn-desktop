mod agent;
mod http_client;
mod tray;

use agent::AgentProcess;
use serde_json::Value;
use std::sync::Mutex;
use tauri::AppHandle;
use tauri_plugin_autostart::MacosLauncher;

// ── Tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
async fn agent_get(app: AppHandle, path: String) -> Result<Value, String> {
    http_client::get(&app, &path).await
}

#[tauri::command]
async fn agent_post(app: AppHandle, path: String, body: String) -> Result<Value, String> {
    http_client::post(&app, &path, &body).await
}

#[tauri::command]
async fn agent_delete(app: AppHandle, path: String) -> Result<Value, String> {
    http_client::delete(&app, &path).await
}

#[tauri::command]
async fn start_agent_cmd(app: AppHandle) -> Result<(), String> {
    agent::start_agent(&app, 7071).map_err(|e| e.to_string())
}

#[tauri::command]
async fn stop_agent_cmd(app: AppHandle) -> Result<(), String> {
    agent::stop_agent(&app);
    Ok(())
}

// ── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_shell::init())
        .manage(AgentProcess(Mutex::new(None)))
        .setup(|app| {
            tray::setup_tray(app)?;

            // Auto-start agent on launch
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = agent::start_agent(&handle, 7071) {
                    eprintln!("Failed to start agent: {e}");
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide instead of close to keep running in tray
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            agent_get,
            agent_post,
            agent_delete,
            start_agent_cmd,
            stop_agent_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
