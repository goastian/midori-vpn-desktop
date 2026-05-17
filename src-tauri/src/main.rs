// main.rs — entry point for non-macOS
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "linux")]
fn configure_linux_appimage_environment() {
    if std::env::var_os("APPIMAGE").is_none() {
        return;
    }

    for (key, value) in [
        ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
        ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
        ("GDK_BACKEND", "x11"),
    ] {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_appimage_environment() {}

fn main() {
    configure_linux_appimage_environment();
    midorivpn_desktop_lib::run();
}
