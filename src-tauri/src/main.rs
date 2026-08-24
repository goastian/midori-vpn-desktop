#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Linux is the only supported production desktop target. macOS and Windows
// implementations remain in source for future work, but are deliberately
// blocked from building or packaging until their native networking paths have
// an end-to-end certification.
#[cfg(any(target_os = "macos", target_os = "windows"))]
compile_error!("MidoriVPN Desktop production builds are currently supported on Linux only");

// main.rs — Linux entry point

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

fn main() {
    configure_linux_appimage_environment();
    midorivpn_desktop_lib::run();
}
