//! Tauri command surface. Every `#[tauri::command]` here is callable from
//! the JS frontend via `invoke('cmd_name', { args })`.

use crate::client::{self, SharedState, UiMessage};
use crate::identity;
use crate::protocol::{MemberInfo, ServerId, ServerInfo};
use serde::Serialize;
use tauri::{AppHandle, State};

fn err_to_string(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[derive(Serialize)]
pub struct IdentityView {
    pub user_id:      String,
    pub display_name: String,
    pub kem_pk_b64:   String,
    pub sig_pk_b64:   String,
}

impl From<&crate::identity::Identity> for IdentityView {
    fn from(id: &crate::identity::Identity) -> Self {
        Self {
            user_id:      id.user_id.to_string(),
            display_name: id.display_name.clone(),
            kem_pk_b64:   id.kem_pk_b64.clone(),
            sig_pk_b64:   id.sig_pk_b64.clone(),
        }
    }
}

#[tauri::command]
pub async fn cmd_load_identity(
    state: State<'_, SharedState>,
) -> Result<Option<IdentityView>, String> {
    let id = identity::load().map_err(err_to_string)?;
    if let Some(id) = id {
        let view = IdentityView::from(&id);
        let mut s = state.lock().await;
        s.identity = Some(id);
        Ok(Some(view))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn cmd_reset_identity(
    state: State<'_, SharedState>,
) -> Result<(), String> {
    identity::delete().map_err(err_to_string)?;
    let mut s = state.lock().await;
    s.identity = None;
    s.channels.clear();
    Ok(())
}

#[tauri::command]
pub async fn cmd_connect(
    state: State<'_, SharedState>,
    app: AppHandle,
    url: String,
) -> Result<(), String> {
    client::connect(state.inner().clone(), app, url).await.map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_register(
    state: State<'_, SharedState>,
    display_name: String,
) -> Result<IdentityView, String> {
    let id = client::register_flow(state.inner(), display_name)
        .await
        .map_err(err_to_string)?;
    Ok(IdentityView::from(&id))
}

#[tauri::command]
pub async fn cmd_login(
    state: State<'_, SharedState>,
) -> Result<IdentityView, String> {
    let id = client::login_flow(state.inner()).await.map_err(err_to_string)?;
    Ok(IdentityView::from(&id))
}

#[tauri::command]
pub async fn cmd_list_servers(
    state: State<'_, SharedState>,
) -> Result<Vec<ServerInfo>, String> {
    client::list_servers_flow(state.inner()).await.map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_create_server(
    state: State<'_, SharedState>,
    name: String,
) -> Result<String, String> {
    let id = client::create_server_flow(state.inner(), name)
        .await
        .map_err(err_to_string)?;
    Ok(id.to_string())
}

#[tauri::command]
pub async fn cmd_join_server(
    state: State<'_, SharedState>,
    server_id: ServerId,
) -> Result<(), String> {
    client::join_server_flow(state.inner(), server_id)
        .await
        .map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_leave_server(
    state: State<'_, SharedState>,
    server_id: ServerId,
) -> Result<(), String> {
    client::leave_server_flow(state.inner(), server_id)
        .await
        .map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_send_message(
    state: State<'_, SharedState>,
    server_id: ServerId,
    plaintext: String,
) -> Result<(), String> {
    client::send_message_flow(state.inner(), server_id, plaintext)
        .await
        .map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_list_members(
    state: State<'_, SharedState>,
    server_id: ServerId,
) -> Result<Vec<MemberInfo>, String> {
    client::list_members_flow(state.inner(), server_id)
        .await
        .map_err(err_to_string)
}

#[tauri::command]
pub async fn cmd_get_history(
    state: State<'_, SharedState>,
    server_id: ServerId,
) -> Result<Vec<UiMessage>, String> {
    client::get_history_flow(state.inner(), server_id)
        .await
        .map_err(err_to_string)
}
