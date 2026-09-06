// broker-desktop/src-tauri/src/main.rs
// Tauri 2.x app entry point.
//
// Phase 1: scaffold only — just shows "Hello broker" window on each platform.
// Phase 2-6: mTLS, REST/WS, tray, notifications, auto-update, polish (see
// docs/DESIGN-TAURI-DESKTOP.md §6).

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    broker_desktop_lib::run();
}
