// Linux XDG autostart management. Writes/removes
// ~/.config/autostart/midorivpn.desktop so the GUI launches at login.
//
// We deliberately do NOT use a systemd user unit:
//   * no DBus socket activation needed
//   * works in containerized desktops (Snap/Flatpak host scenarios) and on
//     non-systemd init systems (runit/openrc)
//   * users can disable it from gnome-tweaks / KDE Autostart UI directly.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use tauri::AppHandle;
#[cfg(not(target_os = "linux"))]
use tauri_plugin_autostart::ManagerExt;

const FILE_NAME: &str = "midorivpn.desktop";

fn autostart_dir() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("autostart"));
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config").join("autostart"))
}

fn autostart_path() -> Option<PathBuf> {
    autostart_dir().map(|d| d.join(FILE_NAME))
}

fn autostart_executable_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    if let Some(appimage) = std::env::var_os("APPIMAGE") {
        if !appimage.is_empty() {
            return Ok(make_absolute(PathBuf::from(appimage)));
        }
    }

    std::env::current_exe()
        .map(make_absolute)
        .map_err(|e| format!("cannot resolve executable path: {e}"))
}

fn make_absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(&path))
        .unwrap_or(path)
}

fn desktop_exec_path(path: &Path) -> Result<String, String> {
    let raw = path.as_os_str().to_string_lossy();
    if raw.chars().any(|c| c == '\n' || c == '\r') {
        return Err("executable path contains a newline".to_string());
    }

    let escaped = raw
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$");
    Ok(format!("\"{escaped}\""))
}

fn desktop_body_for_exec(exec_path: &Path) -> Result<String, String> {
    let exec = desktop_exec_path(exec_path)?;
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=MidoriVPN\n\
         GenericName=Privacy Mesh VPN\n\
         Comment=Start MidoriVPN mesh on login\n\
         Comment[es]=Iniciar la red mesh de MidoriVPN al iniciar sesion\n\
         Exec={exec} --autostart\n\
         Icon=midorivpn\n\
         Terminal=false\n\
         Categories=Network;\n\
         StartupNotify=false\n\
         X-GNOME-Autostart-enabled=true\n\
         X-GNOME-Autostart-Delay=5\n\
         X-MidoriVPN-Managed=true\n"
    ))
}

fn autostart_file_enabled(path: &Path) -> bool {
    let Ok(body) = fs::read_to_string(path) else {
        return path.exists();
    };

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("Hidden") && value.eq_ignore_ascii_case("true") {
            return false;
        }
        if key.eq_ignore_ascii_case("X-GNOME-Autostart-enabled")
            && value.eq_ignore_ascii_case("false")
        {
            return false;
        }
    }

    true
}

#[tauri::command]
#[cfg(target_os = "linux")]
pub fn autostart_is_enabled() -> bool {
    autostart_path()
        .map(|p| p.exists() && autostart_file_enabled(&p))
        .unwrap_or(false)
}

#[tauri::command]
#[cfg(not(target_os = "linux"))]
pub fn autostart_is_enabled(app: AppHandle) -> bool {
    app.autolaunch().is_enabled().unwrap_or(false)
}

#[tauri::command]
#[cfg(target_os = "linux")]
pub fn autostart_set(enabled: bool) -> Result<(), String> {
    let path = autostart_path().ok_or_else(|| "no HOME directory".to_string())?;
    if enabled {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // Write atomically: temp + rename so a crash mid-write doesn't leave a
        // half-empty desktop file the launcher will choke on.
        let tmp = path.with_extension("desktop.tmp");
        let body = desktop_body_for_exec(&autostart_executable_path()?)?;
        fs::write(&tmp, body).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    } else if path.exists() {
        match fs::remove_file(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

#[tauri::command]
#[cfg(not(target_os = "linux"))]
pub fn autostart_set(app: AppHandle, enabled: bool) -> Result<(), String> {
    let autostart = app.autolaunch();
    if enabled {
        autostart.enable()
    } else {
        autostart.disable()
    }
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{autostart_file_enabled, desktop_body_for_exec, desktop_exec_path};
    use std::fs;
    use std::path::Path;

    #[test]
    fn desktop_exec_path_quotes_spaces_and_special_chars() {
        let escaped = desktop_exec_path(Path::new("/tmp/Midori VPN $Build/App\"Run"))
            .expect("path should escape");

        assert_eq!(escaped, "\"/tmp/Midori VPN \\$Build/App\\\"Run\"");
    }

    #[test]
    fn desktop_body_runs_in_autostart_mode() {
        let body = desktop_body_for_exec(Path::new("/opt/MidoriVPN/midorivpn-desktop"))
            .expect("desktop body");

        assert!(body.contains("Exec=\"/opt/MidoriVPN/midorivpn-desktop\" --autostart"));
        assert!(body.contains("X-GNOME-Autostart-Delay=5"));
    }

    #[test]
    fn disabled_desktop_entry_is_not_reported_enabled() {
        let path = std::env::temp_dir().join(format!(
            "midorivpn-autostart-test-{}.desktop",
            std::process::id()
        ));
        fs::write(&path, "[Desktop Entry]\nHidden=true\n").expect("write temp desktop");

        assert!(!autostart_file_enabled(&path));

        let _ = fs::remove_file(path);
    }
}
