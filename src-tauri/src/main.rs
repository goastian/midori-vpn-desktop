// main.rs — entry point for non-macOS
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    midorivpn_desktop_lib::run();
}
