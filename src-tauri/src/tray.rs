use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Manager,
};

/// Fully quit the application.
/// Called from both the tray menu and the GUI quit button.
pub fn quit_application(app: &AppHandle) {
    // Let the global RunEvent::Exit handler perform the shutdown/revoke path
    // exactly once to avoid duplicate polkit prompts.
    app.exit(0);
}

pub fn setup_tray(app: &App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "Connect VPN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Disconnect VPN", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&open, &connect, &disconnect, &quit])?;

    let icon = Image::from_bytes(include_bytes!("../icons/32x32.png"))?;

    TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .tooltip("MidoriVPN")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
            "connect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::http_client::post(&app, "vpn/connect", "{}").await;
                });
            }
            "disconnect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::http_client::post(&app, "vpn/disconnect", "{}").await;
                });
            }
            "quit" => {
                quit_application(app);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}
