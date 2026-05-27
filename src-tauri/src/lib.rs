//! Tauri runtime entry. `main.rs` delegates here so we can keep the bin
//! short and also expose the library form for `tauri-cli`.

mod client;
mod commands;
mod crypto;
mod identity;
mod protocol;
mod state;

use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pq_chat_client_lib=debug".into()),
        )
        .init();

    let shared: client::SharedState = Arc::new(Mutex::new(state::ClientState::new()));

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(shared)
        .invoke_handler(tauri::generate_handler![
            commands::cmd_load_identity,
            commands::cmd_reset_identity,
            commands::cmd_connect,
            commands::cmd_register,
            commands::cmd_login,
            commands::cmd_list_servers,
            commands::cmd_create_server,
            commands::cmd_join_server,
            commands::cmd_leave_server,
            commands::cmd_send_message,
            commands::cmd_list_members,
            commands::cmd_get_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
