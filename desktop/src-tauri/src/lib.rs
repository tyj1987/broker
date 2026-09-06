// broker-desktop/src-tauri/src/lib.rs
// Shared library entry — used by both main.rs (binary) and Tauri mobile builds.

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Phase 4 placeholder: tray icon state machine
            // Phase 3 placeholder: WebSocket re-subscribe on app start

            // Log app version on startup
            let app_handle = app.handle();
            let version = app.package_info().version.to_string();
            tracing::info!(version = %version, "broker-desktop started");

            // Phase 1: show "Hello broker" in main window
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ = window.set_title(&format!("Secret Broker {}", version));
            }

            Ok(())
        })
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
