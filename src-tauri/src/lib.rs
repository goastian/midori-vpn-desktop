mod agent;
mod autostart;
mod http_client;
mod security;
mod tray;

use agent::AgentProcess;
use agent::AgentSupervisorStop;
use agent::AgentToken;
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::AppHandle;
use tauri::Manager;
use tauri_plugin_autostart::MacosLauncher;

#[cfg(target_os = "linux")]
fn configure_linux_appimage_graphics() {
    if std::env::var_os("APPIMAGE").is_none() {
        return;
    }

    // Some WebKitGTK/AppImage combinations abort before first paint while
    // creating an EGL display. Disable the DMABuf renderer only for AppImage
    // launches, and keep any explicit user override intact.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
    if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    }
    if std::env::var_os("GDK_BACKEND").is_none() {
        std::env::set_var("GDK_BACKEND", "x11");
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_appimage_graphics() {}

fn is_background_start_arg(arg: &str) -> bool {
    matches!(arg, "--autostart" | "--minimized" | "--hidden")
}

fn is_background_start_os_arg(arg: &OsStr) -> bool {
    arg.to_str().map(is_background_start_arg).unwrap_or(false)
}

fn is_background_launch() -> bool {
    std::env::args_os().any(|arg| is_background_start_os_arg(&arg))
}

fn reveal_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

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

fn config_value(path: &Path, key: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        let value = value.trim().trim_matches(['\'', '"']);
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn configured_authentik_issuer() -> Option<String> {
    let mut paths = vec![
        PathBuf::from(".env"),
        PathBuf::from("config.env"),
        PathBuf::from("/etc/midorivpn/config.env"),
    ];
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(config_home).join("midorivpn/config.env"));
    } else if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".config/midorivpn/config.env"));
    }

    let mut issuer = paths
        .iter()
        .filter_map(|path| config_value(path, "AUTHENTIK_ISSUER"))
        .next_back();
    if let Ok(environment_issuer) = std::env::var("AUTHENTIK_ISSUER") {
        if !environment_issuer.trim().is_empty() {
            issuer = Some(environment_issuer);
        }
    }
    issuer
}

fn is_allowed_oauth_url(raw: &str, configured_issuer: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    let Ok(issuer) = reqwest::Url::parse(configured_issuer) else {
        return false;
    };
    if url.scheme() != "https" || issuer.scheme() != "https" {
        return false;
    }
    url.host_str() == issuer.host_str()
        && url.port_or_known_default() == issuer.port_or_known_default()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path().starts_with("/application/o/")
}

#[tauri::command]
async fn open_oauth_url(_app: AppHandle, url: String) -> Result<(), String> {
    let issuer = configured_authentik_issuer()
        .ok_or_else(|| "AUTHENTIK_ISSUER is not configured".to_string())?;
    if !is_allowed_oauth_url(&url, &issuer) {
        return Err("OAuth URL is not allowed".to_string());
    }
    open::that(url).map_err(|e| e.to_string())
}

// ── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    configure_linux_appimage_graphics();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Manual re-launch opens the UI; session autostart keeps running in tray.
            if !args.iter().any(|arg| is_background_start_arg(arg)) {
                reveal_main_window(app);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .manage(AgentProcess(Mutex::new(None)))
        .manage(AgentToken(Mutex::new(String::new())))
        .manage(AgentSupervisorStop(Arc::new(std::sync::atomic::AtomicBool::new(false))))
        .setup(|app| {
            tray::setup_tray(app)?;

            if is_background_launch() {
                hide_main_window(app.handle());
            } else {
                reveal_main_window(app.handle());
            }

            // Start the agent supervisor (keeps the agent alive across crashes).
            let handle = app.handle().clone();
            agent::start_supervisor(handle, 7071);
            agent::start_event_relay(app.handle().clone(), 7071);

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide instead of close to keep running in tray. Ignore hide()
            // failures (e.g. window already destroyed during shutdown) — a
            // panic here would tear down the whole Tauri event loop.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if let Err(e) = window.hide() {
                    eprintln!("window hide on close request failed: {e}");
                }
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
            open_oauth_url,
            agent::agent_has_caps,
            agent::grant_agent_permissions,
            agent::grant_dns_protection_caps,
            agent::revert_agent_permissions,
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

#[cfg(test)]
mod tests {
    use super::{is_allowed_oauth_url, is_background_start_arg};

    #[test]
    fn detects_background_start_flags() {
        assert!(is_background_start_arg("--autostart"));
        assert!(is_background_start_arg("--minimized"));
        assert!(is_background_start_arg("--hidden"));
        assert!(!is_background_start_arg("--help"));
    }

    #[test]
    fn allows_only_configured_oauth_origin() {
        let issuer = "https://identity.example.com/application/o/vpn/";
        assert!(is_allowed_oauth_url(
            "https://identity.example.com/application/o/authorize/?client_id=x",
            issuer
        ));

        assert!(!is_allowed_oauth_url(
            "http://identity.example.com/application/o/authorize/",
            issuer
        ));
        assert!(!is_allowed_oauth_url(
            "https://evil.example/application/o/authorize/",
            issuer
        ));
        assert!(!is_allowed_oauth_url(
            "https://identity.example.com.evil.test/application/o/",
            issuer
        ));
        assert!(!is_allowed_oauth_url(
            "https://identity.example.com/not-oauth",
            issuer
        ));
    }
}
