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
use std::path::PathBuf;

const FILE_NAME: &str = "midorivpn.desktop";

/// Bundled .desktop body. Kept in source so we don't have to ship a
/// separate data file inside the AppImage.
const DESKTOP_BODY: &str = include_str!("../../packaging/autostart/midorivpn.desktop");

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

#[tauri::command]
pub fn autostart_is_enabled() -> bool {
    autostart_path().map(|p| p.exists()).unwrap_or(false)
}

#[tauri::command]
pub fn autostart_set(enabled: bool) -> Result<(), String> {
    let path = autostart_path().ok_or_else(|| "no HOME directory".to_string())?;
    if enabled {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // Write atomically: temp + rename so a crash mid-write doesn't leave a
        // half-empty desktop file the launcher will choke on.
        let tmp = path.with_extension("desktop.tmp");
        fs::write(&tmp, DESKTOP_BODY).map_err(|e| e.to_string())?;
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
