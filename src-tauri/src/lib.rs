mod agent;
mod autostart;
mod http_client;
mod security;
mod tray;

use agent::AgentProcess;
use agent::AgentSupervisorStop;
use agent::AgentToken;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tauri::AppHandle;
use tauri::Manager;
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

#[tauri::command]
async fn restart_agent_cmd(app: AppHandle) -> Result<(), String> {
    agent::restart_agent(app, 7071)
}

/// Quit the application fully — stops the agent and exits the process.
/// Mirrors the tray "Quit" menu item so the user can exit from the GUI too.
#[tauri::command]
fn quit_app(app: AppHandle) {
    tray::quit_application(&app);
}
#[tauri::command]
fn security_check() -> Vec<security::SecurityIssue> {
    security::check()
}

// ── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // When a second instance launches, focus the existing window.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_shell::init())
        .manage(AgentProcess(Mutex::new(None)))
        .manage(AgentToken(Mutex::new(String::new())))
        .manage(AgentSupervisorStop(Arc::new(std::sync::atomic::AtomicBool::new(false))))
        .setup(|app| {
            tray::setup_tray(app)?;

            // Start the agent supervisor (keeps the agent alive across crashes).
            let handle = app.handle().clone();
            agent::start_supervisor(handle, 7071);

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
            restart_agent_cmd,
            quit_app,
            security_check,
            agent::agent_has_caps,
            agent::grant_agent_permissions,
            agent::revert_agent_permissions,
            agent::get_agent_token,
            autostart::autostart_is_enabled,
            autostart::autostart_set,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // Safety net: on any exit path stop agent (15 s graceful) then
            // revert capabilities so the binary is left without caps.
            if let tauri::RunEvent::Exit = event {
                agent::stop_agent(app_handle);
                // Revoke only when caps are currently present, otherwise skip
                // to avoid unnecessary polkit prompts on systems where the
                // agent binary is already clean.
                if agent::agent_has_caps() && !agent::revert_agent_permissions() {
                    eprintln!("[midorivpn] warning: could not revert agent capabilities — run 'sudo setcap -r /usr/local/bin/midorivpn-agent' manually");
                }
            }
        });
}
