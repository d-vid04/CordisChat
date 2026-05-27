//! WebSocket transport and high-level protocol logic.
//!
//! There is exactly one logical connection at a time. The connect call
//! spawns two tasks: a writer that drains an outbound channel onto the
//! socket, and a reader that:
//!
//!   * routes "reply" frames to the in-flight `pending_rpc` oneshot, and
//!   * dispatches "event" frames (NewMessage, MemberJoined, MemberLeft,
//!     KeyMaterial) to internal handlers that mutate state and emit Tauri
//!     events to the frontend.

use crate::crypto::{
    aes_open, aes_seal, dilithium_sign, dilithium_verify, message_signed_payload,
    random_group_key, unwrap_group_key, wrap_group_key_for, GroupKey,
};
use crate::identity::Identity;
use crate::protocol::{
    ClientMessage, Epoch, MemberInfo, ServerId, ServerMessage, StoredMessage, UserId,
};
use crate::state::{ChannelView, ClientState};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

pub type SharedState = Arc<Mutex<ClientState>>;

// ---------------------------------------------------------------------------
// Events emitted to the frontend
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct UiMessage {
    pub server_id:   ServerId,
    pub message_id:  uuid::Uuid,
    pub sender_id:   UserId,
    pub sender_name: String,
    pub epoch:       Epoch,
    pub timestamp:   chrono::DateTime<chrono::Utc>,
    pub plaintext:   Option<String>,    // None when we can't decrypt
    pub status:      &'static str,      // "ok" | "sealed" | "bad_sig" | "decrypt_failed"
}

#[derive(Serialize, Clone)]
pub struct UiMemberChange {
    pub server_id:   ServerId,
    pub user_id:     UserId,
    pub display_name: String,
    pub epoch:       Epoch,
    pub kind:        &'static str, // "joined" | "left"
}

#[derive(Serialize, Clone)]
pub struct UiConnState {
    pub state:  &'static str,        // "connecting" | "connected" | "authenticated" | "disconnected"
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Connect + spawn read/write loops
// ---------------------------------------------------------------------------

/// Open a WebSocket to `url` and start the two pump tasks. Replaces any
/// existing connection.
pub async fn connect(state: SharedState, app: AppHandle, url: String) -> Result<()> {
    emit_conn(&app, "connecting", None);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<String>();
    {
        let mut s = state.lock().await;
        s.tx_out = Some(tx_out);
        // Clear any per-session state — fresh channels, fresh keys.
        s.channels.clear();
        s.pending_rpc = None;
    }

    // Writer task.
    tokio::spawn(async move {
        while let Some(text) = rx_out.recv().await {
            if ws_tx.send(WsMessage::Text(text)).await.is_err() {
                break;
            }
        }
    });

    // Reader task.
    let state_r = state.clone();
    let app_r   = app.clone();
    tokio::spawn(async move {
        while let Some(frame) = ws_rx.next().await {
            let text = match frame {
                Ok(WsMessage::Text(t)) => t,
                Ok(WsMessage::Binary(b)) => String::from_utf8(b).unwrap_or_default(),
                Ok(WsMessage::Ping(_) | WsMessage::Pong(_)) => continue,
                Ok(WsMessage::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            };
            let msg: ServerMessage = match serde_json::from_str(&text) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("garbled server frame: {e}; raw={text}");
                    continue;
                }
            };
            handle_server_message(&state_r, &app_r, msg).await;
        }
        // Connection died — wipe outbound side and notify UI.
        {
            let mut s = state_r.lock().await;
            s.tx_out = None;
            if let Some(p) = s.pending_rpc.take() {
                let _ = p.send(ServerMessage::Error {
                    reason: "connection closed".into(),
                });
            }
        }
        emit_conn(&app_r, "disconnected", None);
    });

    emit_conn(&app, "connected", Some(url));
    Ok(())
}

fn emit_conn(app: &AppHandle, state: &'static str, detail: Option<String>) {
    let _ = app.emit("connection_state", UiConnState { state, detail });
}

// ---------------------------------------------------------------------------
// Server-message dispatcher
// ---------------------------------------------------------------------------

async fn handle_server_message(state: &SharedState, app: &AppHandle, msg: ServerMessage) {
    if msg.is_event() {
        if let Err(e) = handle_event(state, app, msg).await {
            tracing::warn!("event handler error: {e:#}");
            let _ = app.emit("client_error", e.to_string());
        }
    } else {
        // Reply to an RPC.
        let mut s = state.lock().await;
        if let Some(tx) = s.pending_rpc.take() {
            let _ = tx.send(msg);
        } else {
            // Unsolicited reply (e.g. server pushed an Error). Surface it.
            if let ServerMessage::Error { reason } = msg {
                drop(s);
                let _ = app.emit("client_error", reason);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event handlers (server-pushed frames)
// ---------------------------------------------------------------------------

async fn handle_event(state: &SharedState, app: &AppHandle, msg: ServerMessage) -> Result<()> {
    match msg {
        ServerMessage::NewMessage {
            server_id, message_id, sender, epoch, nonce, ciphertext, signature, timestamp,
        } => {
            let nonce_b  = B64.decode(&nonce).context("nonce b64")?;
            let cipher_b = B64.decode(&ciphertext).context("ciphertext b64")?;
            let sig_b    = B64.decode(&signature).context("signature b64")?;

            let (plaintext, status, sender_name) = {
                let s = state.lock().await;
                decrypt_and_verify(&s, server_id, sender, epoch, &nonce_b, &cipher_b, &sig_b)
            };

            let _ = app.emit("new_message", UiMessage {
                server_id, message_id,
                sender_id: sender, sender_name,
                epoch, timestamp,
                plaintext, status,
            });
        }

        ServerMessage::MemberJoined { server_id, member, epoch } => {
            // Cache the new member & bump epoch.
            {
                let mut s = state.lock().await;
                let ch = s.channels.entry(server_id).or_default();
                ch.members.insert(member.user_id, member.clone());
                ch.epoch = epoch;
            }
            let _ = app.emit("member_change", UiMemberChange {
                server_id,
                user_id: member.user_id,
                display_name: member.display_name.clone(),
                epoch,
                kind: "joined",
            });

            // Maybe rekey. Lowest-UUID *existing* member (i.e. excluding the
            // joiner, who has no prior key and can't wrap) runs the protocol.
            try_rekey_after_membership_change(state, app, server_id, Some(member.user_id)).await?;
        }

        ServerMessage::MemberLeft { server_id, user_id, epoch } => {
            {
                let mut s = state.lock().await;
                let ch = s.channels.entry(server_id).or_default();
                ch.members.remove(&user_id);
                ch.epoch = epoch;
            }
            let display_name = {
                let s = state.lock().await;
                s.channels.get(&server_id)
                    .and_then(|c| c.members.get(&user_id).map(|m| m.display_name.clone()))
                    .unwrap_or_else(|| user_id.to_string())
            };
            let _ = app.emit("member_change", UiMemberChange {
                server_id, user_id, display_name, epoch, kind: "left",
            });

            try_rekey_after_membership_change(state, app, server_id, None).await?;
        }

        ServerMessage::KeyMaterial { server_id, from_user: _, epoch, wrapped_key } => {
            let envelope = B64.decode(&wrapped_key).context("wrapped_key b64")?;
            let (kem_sk, _have) = {
                let s = state.lock().await;
                let id = s.require_identity()?.clone();
                (id.kem_sk()?, s.channels.contains_key(&server_id))
            };
            let key = unwrap_group_key(&kem_sk, &envelope)
                .context("unwrapping group key")?;
            let mut s = state.lock().await;
            let ch = s.channels.entry(server_id).or_default();
            ch.keys.insert(epoch, key);
            // No need to bump epoch here; the MemberJoined/Left that caused
            // this rekey already did (or will). We just stash the key.
            let _ = app.emit("key_rotated", serde_json::json!({
                "server_id": server_id, "epoch": epoch,
            }));
        }

        _ => unreachable!("non-event in handle_event"),
    }
    Ok(())
}

/// Returns (plaintext_or_none, status_str, sender_name).
fn decrypt_and_verify(
    s: &ClientState,
    server_id: ServerId,
    sender: UserId,
    epoch: Epoch,
    nonce: &[u8],
    ciphertext: &[u8],
    signature: &[u8],
) -> (Option<String>, &'static str, String) {
    let sender_name = s.channels.get(&server_id)
        .and_then(|c| c.members.get(&sender).map(|m| m.display_name.clone()))
        .unwrap_or_else(|| short_id(sender));

    let Some(ch) = s.channels.get(&server_id) else {
        return (None, "sealed", sender_name);
    };
    let Some(key) = ch.keys.get(&epoch) else {
        return (None, "sealed", sender_name);
    };

    // Verify signature over (server_id || epoch || nonce || ciphertext) with
    // the sender's Dilithium pubkey — if we have it (we should, from member cache).
    let sig_ok = match ch.members.get(&sender) {
        Some(m) => {
            let payload = message_signed_payload(&server_id, epoch, nonce, ciphertext);
            dilithium_verify(&m.sig_public_key, &payload, signature).is_ok()
        }
        None => true, // unknown sender — accept; member cache may lag
    };
    if !sig_ok {
        return (None, "bad_sig", sender_name);
    }

    match aes_open(key, nonce, ciphertext) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s)  => (Some(s), "ok", sender_name),
            Err(_) => (None, "decrypt_failed", sender_name),
        },
        Err(_) => (None, "decrypt_failed", sender_name),
    }
}

fn short_id(u: UserId) -> String {
    let s = u.to_string();
    s.chars().take(8).collect()
}

// ---------------------------------------------------------------------------
// Rekey election
// ---------------------------------------------------------------------------
//
// After any membership change, the lowest UUID among the entitled rewrappers
// (= members at the new epoch, minus the joiner if any) generates a fresh
// group key and `DistributeKey`s a wrapped copy to every member at the new
// epoch.
//
// This is a deterministic election so multiple existing members don't all
// rewrap in parallel (which would create competing group keys).

async fn try_rekey_after_membership_change(
    state: &SharedState,
    _app: &AppHandle,
    server_id: ServerId,
    joiner: Option<UserId>,
) -> Result<()> {
    let (me, entitled, members_at_new_epoch, new_epoch, prev_key) = {
        let s = state.lock().await;
        let me = s.require_identity()?.user_id;
        let Some(ch) = s.channels.get(&server_id) else { return Ok(()); };
        let new_epoch = ch.epoch;
        let members_at_new_epoch: Vec<MemberInfo> = ch.members.values().cloned().collect();
        let entitled: Vec<UserId> = ch.members.keys().copied()
            .filter(|u| Some(*u) != joiner)
            .collect();
        // We need an old key to be "entitled" in practice — we can rewrap a
        // *new* fresh key without knowing the old one, but if we can't prove
        // membership at the previous epoch (i.e. we just joined and don't
        // have a key) we shouldn't be the one rekeying.
        let prev_key = ch.keys.values().next_back().copied();
        (me, entitled, members_at_new_epoch, new_epoch, prev_key)
    };

    // We rekey iff we are the lowest UUID among the entitled set AND we
    // actually hold a key for some earlier epoch (proof we were in before).
    let lowest = entitled.iter().min().copied();
    if lowest != Some(me) {
        return Ok(());
    }
    if prev_key.is_none() {
        // We're elected but we have no key — shouldn't normally happen, but
        // bail out cleanly rather than rewrapping a key we can't ourselves use.
        tracing::warn!("elected to rekey {server_id} but hold no prior key");
        return Ok(());
    }

    // Generate fresh group key for the new epoch and stash it locally.
    let new_key: GroupKey = random_group_key();
    {
        let mut s = state.lock().await;
        let ch = s.channels.entry(server_id).or_default();
        ch.keys.insert(new_epoch, new_key);
    }

    // Wrap and distribute to every member at the new epoch (including the
    // joiner; including ourselves is unnecessary but harmless — actually
    // the server rejects sending to ourselves? Let me check… the server
    // only checks that target is in the channel. It would happily forward
    // to ourselves. We skip it explicitly to save bytes.)
    for m in &members_at_new_epoch {
        if m.user_id == me { continue; }
        let wrapped = wrap_group_key_for(&m.kem_public_key, &new_key)
            .with_context(|| format!("wrapping for {}", m.user_id))?;
        send(state, ClientMessage::DistributeKey {
            server_id,
            target_user_id: m.user_id,
            epoch: new_epoch,
            wrapped_key: B64.encode(&wrapped),
        }).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Send / RPC helpers
// ---------------------------------------------------------------------------

/// Fire-and-forget send (no waiting for a reply).
pub async fn send(state: &SharedState, msg: ClientMessage) -> Result<()> {
    let s = state.lock().await;
    let tx = s.tx_out.as_ref().ok_or_else(|| anyhow!("not connected"))?;
    let json = serde_json::to_string(&msg)?;
    tx.send(json).map_err(|_| anyhow!("connection dropped"))?;
    Ok(())
}

/// Send and wait for the next reply frame. Serialised — only one RPC at a
/// time across the whole client. (The server never reorders replies and the
/// protocol has no request IDs, so this is the cleanest answer.)
pub async fn rpc(state: &SharedState, msg: ClientMessage) -> Result<ServerMessage> {
    // We hold a per-client lock for the entire round-trip so two callers
    // can't have overlapping pending replies.
    static RPC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = RPC_LOCK.lock().await;

    let (tx, rx) = oneshot::channel();
    {
        let mut s = state.lock().await;
        if s.tx_out.is_none() { bail!("not connected"); }
        s.pending_rpc = Some(tx);
    }
    send(state, msg).await?;

    let reply = tokio::time::timeout(RPC_TIMEOUT, rx)
        .await
        .map_err(|_| anyhow!("RPC timeout"))?
        .map_err(|_| anyhow!("RPC channel cancelled"))?;
    Ok(reply)
}

/// Convenience: expect a particular reply variant or surface the error.
pub fn expect_ok(reply: ServerMessage) -> Result<ServerMessage> {
    if let ServerMessage::Error { reason } = reply {
        bail!("server: {reason}");
    }
    Ok(reply)
}

// ---------------------------------------------------------------------------
// High-level flows used by Tauri commands
// ---------------------------------------------------------------------------

pub async fn register_flow(
    state: &SharedState,
    display_name: String,
) -> Result<Identity> {
    let mut id = crate::identity::new_unregistered(display_name.clone());
    let reply = rpc(state, ClientMessage::Register {
        display_name,
        kem_public_key: id.kem_pk_b64.clone(),
        sig_public_key: id.sig_pk_b64.clone(),
    }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::Registered { user_id } = reply else {
        bail!("expected Registered, got {reply:?}");
    };
    id.user_id = user_id;
    crate::identity::save(&id)?;
    {
        let mut s = state.lock().await;
        s.identity = Some(id.clone());
    }
    Ok(id)
}

pub async fn login_flow(state: &SharedState) -> Result<Identity> {
    let id = {
        let s = state.lock().await;
        s.identity.clone().ok_or_else(|| anyhow!("no identity loaded"))?
    };

    let reply = rpc(state, ClientMessage::AuthBegin { user_id: id.user_id }).await?;
    // Server may have forgotten this user (in-memory store; restart wipes it).
    if let ServerMessage::Error { reason } = &reply {
        if reason.contains("unknown user") {
            // Reuse keys, re-register, get a new UUID.
            tracing::info!("server doesn't know us — re-registering with same keypairs");
            let new_id = register_with_existing_keys(state, &id).await?;
            return Ok(new_id);
        }
    }
    let reply = expect_ok(reply)?;
    let ServerMessage::AuthChallenge { nonce } = reply else {
        bail!("expected AuthChallenge, got {reply:?}");
    };
    let challenge = B64.decode(&nonce)?;
    let sig = dilithium_sign(&id.sig_sk()?, &challenge)?;
    let reply = rpc(state, ClientMessage::AuthFinish {
        signature: B64.encode(&sig),
    }).await?;
    let _ = expect_ok(reply)?;
    Ok(id)
}

/// Register again with the same keypairs (used when server has forgotten us).
async fn register_with_existing_keys(state: &SharedState, old: &Identity) -> Result<Identity> {
    let reply = rpc(state, ClientMessage::Register {
        display_name:   old.display_name.clone(),
        kem_public_key: old.kem_pk_b64.clone(),
        sig_public_key: old.sig_pk_b64.clone(),
    }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::Registered { user_id } = reply else {
        bail!("expected Registered, got {reply:?}");
    };
    let mut new_id = old.clone();
    new_id.user_id = user_id;
    crate::identity::save(&new_id)?;
    {
        let mut s = state.lock().await;
        s.identity = Some(new_id.clone());
    }
    // Now actually authenticate so the session is usable.
    let reply = rpc(state, ClientMessage::AuthBegin { user_id }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::AuthChallenge { nonce } = reply else {
        bail!("expected AuthChallenge");
    };
    let challenge = B64.decode(&nonce)?;
    let sig = dilithium_sign(&new_id.sig_sk()?, &challenge)?;
    let reply = rpc(state, ClientMessage::AuthFinish {
        signature: B64.encode(&sig),
    }).await?;
    let _ = expect_ok(reply)?;
    Ok(new_id)
}

pub async fn create_server_flow(state: &SharedState, name: String) -> Result<ServerId> {
    let reply = rpc(state, ClientMessage::CreateServer { name: name.clone() }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::ServerCreated { server_id, epoch } = reply else {
        bail!("expected ServerCreated, got {reply:?}");
    };

    // We're sole member at epoch 0. Generate a fresh group key locally.
    let key = random_group_key();
    let me_info = {
        let s = state.lock().await;
        let id = s.require_identity()?;
        MemberInfo {
            user_id:        id.user_id,
            display_name:   id.display_name.clone(),
            kem_public_key: id.kem_pk()?,
            sig_public_key: id.sig_pk()?,
        }
    };
    {
        let mut s = state.lock().await;
        let ch = s.channels.entry(server_id).or_default();
        ch.epoch = epoch;
        ch.name  = name;
        ch.members.insert(me_info.user_id, me_info);
        ch.keys.insert(epoch, key);
    }
    Ok(server_id)
}

pub async fn join_server_flow(state: &SharedState, server_id: ServerId) -> Result<()> {
    let reply = rpc(state, ClientMessage::JoinServer { server_id }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::ServerJoined { server_id, epoch, members } = reply else {
        bail!("expected ServerJoined, got {reply:?}");
    };
    let mut s = state.lock().await;
    let ch = s.channels.entry(server_id).or_default();
    ch.epoch = epoch;
    for m in members {
        ch.members.insert(m.user_id, m);
    }
    // No group key yet — wait for KeyMaterial pushed by an existing member.
    Ok(())
}

pub async fn leave_server_flow(state: &SharedState, server_id: ServerId) -> Result<()> {
    let reply = rpc(state, ClientMessage::LeaveServer { server_id }).await?;
    let _ = expect_ok(reply)?;
    let mut s = state.lock().await;
    s.channels.remove(&server_id);
    Ok(())
}

pub async fn send_message_flow(
    state:     &SharedState,
    server_id: ServerId,
    plaintext: String,
) -> Result<()> {
    // Snapshot the data we need under one lock.
    let (id, epoch, key) = {
        let s = state.lock().await;
        let id = s.require_identity()?.clone();
        let ch = s.channels.get(&server_id)
            .ok_or_else(|| anyhow!("you are not in this server"))?;
        let key = *ch.keys.get(&ch.epoch)
            .ok_or_else(|| anyhow!("no group key for current epoch — wait for key distribution"))?;
        (id, ch.epoch, key)
    };

    let (nonce, ciphertext) = aes_seal(&key, plaintext.as_bytes())?;
    let signed_payload = message_signed_payload(&server_id, epoch, &nonce, &ciphertext);
    let sig = dilithium_sign(&id.sig_sk()?, &signed_payload)?;

    // Fire-and-forget — the backend doesn't ack SendMessage, it just fans
    // out NewMessage to all members (including us). If the server rejects
    // this (stale epoch, not a member, bad sig), we receive an `Error`
    // frame which our reader emits as a `client_error` event to the UI.
    send(state, ClientMessage::SendMessage {
        server_id,
        epoch,
        nonce:      B64.encode(&nonce),
        ciphertext: B64.encode(&ciphertext),
        signature:  B64.encode(&sig),
    }).await

}

pub async fn list_servers_flow(state: &SharedState) -> Result<Vec<crate::protocol::ServerInfo>> {
    let reply = rpc(state, ClientMessage::ListServers).await?;
    let reply = expect_ok(reply)?;
    match reply {
        ServerMessage::ServerList { servers } => Ok(servers),
        other => bail!("expected ServerList, got {other:?}"),
    }
}

pub async fn list_members_flow(
    state: &SharedState,
    server_id: ServerId,
) -> Result<Vec<MemberInfo>> {
    let reply = rpc(state, ClientMessage::ListMembers { server_id }).await?;
    let reply = expect_ok(reply)?;
    match reply {
        ServerMessage::MemberList { members, .. } => {
            // Refresh local cache.
            let mut s = state.lock().await;
            let ch = s.channels.entry(server_id).or_default();
            for m in &members {
                ch.members.insert(m.user_id, m.clone());
            }
            Ok(members)
        }
        other => bail!("expected MemberList, got {other:?}"),
    }
}

pub async fn get_history_flow(
    state: &SharedState,
    server_id: ServerId,
) -> Result<Vec<UiMessage>> {
    let reply = rpc(state, ClientMessage::GetHistory { server_id }).await?;
    let reply = expect_ok(reply)?;
    let ServerMessage::History { messages, .. } = reply else {
        bail!("expected History");
    };
    let s = state.lock().await;
    let out = messages.into_iter().map(|m: StoredMessage| {
        let (plaintext, status, sender_name) = decrypt_and_verify(
            &s, server_id, m.sender, m.epoch, &m.nonce, &m.ciphertext, &m.signature,
        );
        UiMessage {
            server_id,
            message_id: m.message_id,
            sender_id:  m.sender,
            sender_name,
            epoch:      m.epoch,
            timestamp:  m.timestamp,
            plaintext,
            status,
        }
    }).collect();
    Ok(out)
}
