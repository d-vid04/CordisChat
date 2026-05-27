//! # Post-Quantum Encrypted Group Chat Backend
//!
//! A Rust backend for a Discord-style group chat application with end-to-end
//! encryption using NIST post-quantum cryptography.
//!
//! ## Cryptography
//! - **ML-KEM-768 (Kyber768)**  — post-quantum key encapsulation
//! - **ML-DSA-65 (Dilithium3)** — post-quantum signatures
//! - **AES-256-GCM**            — symmetric authenticated encryption (client-side)
//!
//! ## Architecture
//!
//! The server is a *dumb relay*. It never sees plaintext, never sees group
//! keys, and cannot read messages. It only stores:
//!   * user public keys
//!   * server (channel) membership
//!   * encrypted message blobs and the wrapped key envelopes that clients
//!     produce for each other
//!
//! ### Protocol summary
//!
//! 1. **Register.** A new user generates a Kyber keypair (for receiving
//!    wrapped group keys) and a Dilithium keypair (for signing) on the client.
//!    The public keys are uploaded to the server.
//!
//! 2. **Authenticate.** On connect, the server issues a random 32-byte
//!    challenge. The client signs it with their Dilithium private key and the
//!    server verifies the detached signature against the stored public key.
//!
//! 3. **Create channel.** The creator picks a random 32-byte symmetric group
//!    key locally, then asks the server to create the channel. The creator is
//!    the sole member at epoch 0.
//!
//! 4. **Join.** Server adds the joiner, increments the epoch, and tells
//!    existing members. Any member then runs `kyber768::encapsulate` against
//!    each member's Kyber pubkey (including the joiner) to wrap a freshly
//!    rotated group key, and sends those envelopes to the server, which
//!    delivers each to the right recipient.
//!
//! 5. **Leave.** Same flow as join — the epoch bumps, a remaining member
//!    rewraps a new group key for the surviving members. The departing user
//!    is cryptographically excluded going forward.
//!
//! 6. **Send.** Sender does AES-256-GCM(plaintext) under the current group
//!    key, signs `(channel_id || epoch || ciphertext || nonce)` with
//!    Dilithium, and sends to the server. The server fans out to all online
//!    members and persists the encrypted blob.
//!
//! ## Cargo.toml
//!
//! ```toml
//! [package]
//! name    = "pq-chat-backend"
//! version = "0.1.0"
//! edition = "2021"
//!
//! [dependencies]
//! tokio              = { version = "1",   features = ["full"] }
//! tokio-tungstenite  = "0.21"
//! futures-util       = "0.3"
//! serde              = { version = "1",   features = ["derive"] }
//! serde_json         = "1"
//! uuid               = { version = "1",   features = ["v4", "serde"] }
//! pqcrypto-kyber     = "0.8"
//! pqcrypto-dilithium = "0.5"
//! pqcrypto-traits    = "0.3"
//! dashmap            = "5"
//! anyhow             = "1"
//! chrono             = { version = "0.4", features = ["serde"] }
//! tracing            = "0.1"
//! tracing-subscriber = "0.3"
//! base64             = "0.22"
//! rand               = "0.8"
//! ```

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use uuid::Uuid;

// ============================================================================
// Identifiers & lightweight types
// ============================================================================

pub type UserId    = Uuid;
pub type ServerId  = Uuid;   // a "server" here is a Discord-style channel/guild
pub type Epoch     = u64;

const BIND_ADDR:    &str  = "0.0.0.0:8080";
const CHALLENGE_LEN: usize = 32;
const MAX_HISTORY:  usize  = 500;   // ring-buffer cap per channel

// Convenience: serialize a byte slice as base64 in JSON.
fn b64(b: &[u8]) -> String { B64.encode(b) }

// ============================================================================
// Persisted records
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id:        UserId,
    pub display_name:   String,
    /// Kyber768 public key bytes (clients use this to wrap group keys for us).
    pub kem_public_key: Vec<u8>,
    /// Dilithium3 public key bytes (used to verify our signatures).
    pub sig_public_key: Vec<u8>,
    pub created_at:     DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub message_id: Uuid,
    pub sender:     UserId,
    pub epoch:      Epoch,
    pub nonce:      Vec<u8>,        // 12-byte AES-GCM nonce
    pub ciphertext: Vec<u8>,        // AES-256-GCM(plaintext) under group key
    pub signature:  Vec<u8>,        // Dilithium3 detached signature
    pub timestamp:  DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberInfo {
    pub user_id:        UserId,
    pub display_name:   String,
    pub kem_public_key: Vec<u8>,
    pub sig_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub server_id:    ServerId,
    pub name:         String,
    pub owner_id:     UserId,
    pub member_count: usize,
}

/// Internal per-channel state. Held inside `AppState` behind an `RwLock`.
#[derive(Debug)]
struct ChannelRecord {
    server_id:  ServerId,
    name:       String,
    owner_id:   UserId,
    members:    HashSet<UserId>,
    epoch:      Epoch,
    /// Most recent N encrypted messages, kept for clients that come online
    /// after a message was sent.
    history:    Vec<StoredMessage>,
}

// ============================================================================
// Wire protocol — JSON over WebSocket
// ============================================================================

/// Messages from client → server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// First-time registration. Server returns the assigned `user_id`.
    Register {
        display_name:   String,
        kem_public_key: String, // b64
        sig_public_key: String, // b64
    },
    /// Begin an authenticated session. Server replies with `AuthChallenge`.
    AuthBegin { user_id: UserId },
    /// Detached Dilithium3 signature over the most recent challenge nonce.
    AuthFinish { signature: String /* b64 */ },

    CreateServer { name: String },
    JoinServer   { server_id: ServerId },
    LeaveServer  { server_id: ServerId },

    /// Forward a Kyber-wrapped group key to another member of a channel.
    /// `wrapped_key` is whatever ciphertext the client produced; the server
    /// is opaque to its contents.
    DistributeKey {
        server_id:      ServerId,
        target_user_id: UserId,
        epoch:          Epoch,
        wrapped_key:    String, // b64
    },

    /// Encrypted chat message.
    SendMessage {
        server_id:  ServerId,
        epoch:      Epoch,
        nonce:      String, // b64
        ciphertext: String, // b64
        signature:  String, // b64
    },

    ListServers,
    ListMembers   { server_id: ServerId },
    GetHistory    { server_id: ServerId },

    /// Look up a user's public keys (e.g. before sending them a wrapped key).
    LookupUser    { user_id: UserId },

    Ping,
}

/// Messages from server → client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Registered     { user_id: UserId },
    AuthChallenge  { nonce: String /* b64 */ },
    Authenticated  { user_id: UserId },

    Error          { reason: String },

    ServerCreated  { server_id: ServerId, epoch: Epoch },
    ServerJoined   { server_id: ServerId, epoch: Epoch, members: Vec<MemberInfo> },
    ServerLeft     { server_id: ServerId },

    /// Pushed to existing members when someone joins. They are expected to
    /// produce a fresh wrapped group key and call `DistributeKey`.
    MemberJoined   { server_id: ServerId, member: MemberInfo, epoch: Epoch },
    /// Pushed to remaining members when someone leaves; trigger rekey.
    MemberLeft     { server_id: ServerId, user_id: UserId, epoch: Epoch },

    /// A wrapped group key arrived for us. Decapsulate with our Kyber sk.
    KeyMaterial {
        server_id:   ServerId,
        from_user:   UserId,
        epoch:       Epoch,
        wrapped_key: String, // b64
    },

    NewMessage {
        server_id:  ServerId,
        message_id: Uuid,
        sender:     UserId,
        epoch:      Epoch,
        nonce:      String, // b64
        ciphertext: String, // b64
        signature:  String, // b64
        timestamp:  DateTime<Utc>,
    },

    History     { server_id: ServerId, messages: Vec<StoredMessage> },
    ServerList  { servers:   Vec<ServerInfo> },
    MemberList  { server_id: ServerId, members: Vec<MemberInfo> },
    UserInfo    { user: UserRecord },
    Pong,
}

// ============================================================================
// Shared application state
// ============================================================================

/// A live client connection. `tx` is used by other tasks to push frames at it.
#[derive(Debug)]
struct Session {
    user_id: UserId,
    tx:      mpsc::UnboundedSender<ServerMessage>,
}

pub struct AppState {
    /// All registered users keyed by id.
    users:    DashMap<UserId, UserRecord>,
    /// All channels.
    channels: RwLock<HashMap<ServerId, ChannelRecord>>,
    /// Currently-online users → their outbound queue.
    online:   DashMap<UserId, Session>,
}

impl AppState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            users:    DashMap::new(),
            channels: RwLock::new(HashMap::new()),
            online:   DashMap::new(),
        })
    }

    /// Push a message to a single online user. Silently drops if offline.
    fn push(&self, user: UserId, msg: ServerMessage) {
        if let Some(sess) = self.online.get(&user) {
            let _ = sess.tx.send(msg);
        }
    }

    /// Broadcast to every member of a channel except `except`.
    async fn broadcast(&self, server_id: ServerId, except: Option<UserId>, msg: ServerMessage)
    where
        ServerMessage: Clone,
    {
        let channels = self.channels.read().await;
        let Some(ch) = channels.get(&server_id) else { return; };
        for &uid in &ch.members {
            if Some(uid) == except { continue; }
            self.push(uid, msg.clone());
        }
    }
}

// We need ServerMessage to be Clone for broadcasting.
impl Clone for ServerMessage {
    fn clone(&self) -> Self {
        // Cheap-ish: round-trip through JSON. Avoids hand-implementing Clone
        // for the whole tree. Broadcasts are rare enough that this is fine.
        serde_json::from_str(&serde_json::to_string(self).unwrap()).unwrap()
    }
}

// ============================================================================
// Crypto helpers — server-side
// ============================================================================
//
// The server handles only two crypto operations directly:
//   1. Generating a random challenge for auth.
//   2. Verifying detached Dilithium3 signatures over those challenges.
//
// All other crypto (Kyber encapsulate/decapsulate, AES-GCM, message signing)
// happens on the client.

fn random_challenge() -> Vec<u8> {
    let mut buf = vec![0u8; CHALLENGE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn verify_dilithium_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let pk  = dilithium3::PublicKey::from_bytes(pubkey)
        .map_err(|e| anyhow!("invalid Dilithium3 public key: {e:?}"))?;
    let sig = dilithium3::DetachedSignature::from_bytes(signature)
        .map_err(|e| anyhow!("invalid Dilithium3 signature encoding: {e:?}"))?;
    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| anyhow!("Dilithium3 signature verification failed"))
}

/// Sanity check that a byte string parses as a Kyber768 public key. We don't
/// use the parsed value; we just want to reject obviously malformed ones at
/// registration time.
fn validate_kyber_pubkey(bytes: &[u8]) -> Result<()> {
    kyber768::PublicKey::from_bytes(bytes)
        .map(|_| ())
        .map_err(|e| anyhow!("invalid Kyber768 public key: {e:?}"))
}

// ============================================================================
// Connection handling
// ============================================================================

/// Per-connection auth state.
enum ConnAuth {
    Anonymous,
    Pending  { user_id: UserId, challenge: Vec<u8> },
    Auth     { user_id: UserId },
}

async fn handle_connection(state: Arc<AppState>, raw: TcpStream, peer: SocketAddr) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(raw).await
        .with_context(|| format!("websocket handshake with {peer}"))?;
    tracing::info!(%peer, "client connected");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out_tx, mut out_rx)   = mpsc::unbounded_channel::<ServerMessage>();
    let mut auth = ConnAuth::Anonymous;

    loop {
        tokio::select! {
            // Outgoing: drain anything queued for this client.
            Some(msg) = out_rx.recv() => {
                let json = serde_json::to_string(&msg)?;
                if ws_tx.send(WsMessage::Text(json)).await.is_err() { break; }
            }

            // Incoming: a frame from the client.
            frame = ws_rx.next() => {
                let Some(frame) = frame else { break; };
                let frame = match frame {
                    Ok(f)  => f,
                    Err(e) => { tracing::warn!(%peer, "ws error: {e}"); break; }
                };

                let text = match frame {
                    WsMessage::Text(t)   => t,
                    WsMessage::Binary(b) => String::from_utf8(b).unwrap_or_default(),
                    WsMessage::Ping(p)   => { let _ = ws_tx.send(WsMessage::Pong(p)).await; continue; }
                    WsMessage::Close(_)  => break,
                    _ => continue,
                };

                let req: ClientMessage = match serde_json::from_str(&text) {
                    Ok(v)  => v,
                    Err(e) => {
                        let _ = out_tx.send(ServerMessage::Error {
                            reason: format!("malformed request: {e}"),
                        });
                        continue;
                    }
                };

                if let Err(e) = dispatch(&state, &mut auth, &out_tx, req).await {
                    let _ = out_tx.send(ServerMessage::Error { reason: e.to_string() });
                }
            }
        }
    }

    // Cleanup: drop session entry and any presence info.
    if let ConnAuth::Auth { user_id } = auth {
        state.online.remove(&user_id);
        tracing::info!(%peer, %user_id, "client disconnected");
    } else {
        tracing::info!(%peer, "anonymous client disconnected");
    }
    Ok(())
}

/// Dispatch a single client request. Returns Err on protocol/auth violations
/// — these become a single `Error` frame to the client, the connection stays.
async fn dispatch(
    state:  &Arc<AppState>,
    auth:   &mut ConnAuth,
    out_tx: &mpsc::UnboundedSender<ServerMessage>,
    req:    ClientMessage,
) -> Result<()> {
    use ClientMessage::*;

    // Helper that requires an authenticated session.
    macro_rules! require_auth { () => {{
        match auth {
            ConnAuth::Auth { user_id } => *user_id,
            _ => bail!("not authenticated"),
        }
    }}; }

    match req {
        Ping => { out_tx.send(ServerMessage::Pong)?; }

        // -------- registration / auth -------------------------------------
        Register { display_name, kem_public_key, sig_public_key } => {
            let kem_pk = B64.decode(&kem_public_key).context("kem_public_key not base64")?;
            let sig_pk = B64.decode(&sig_public_key).context("sig_public_key not base64")?;
            validate_kyber_pubkey(&kem_pk)?;
            // Validate Dilithium pk by trying to parse it.
            dilithium3::PublicKey::from_bytes(&sig_pk)
                .map_err(|e| anyhow!("invalid Dilithium3 public key: {e:?}"))?;

            let user_id = Uuid::new_v4();
            let record  = UserRecord {
                user_id,
                display_name,
                kem_public_key: kem_pk,
                sig_public_key: sig_pk,
                created_at: Utc::now(),
            };
            state.users.insert(user_id, record);
            out_tx.send(ServerMessage::Registered { user_id })?;
        }

        AuthBegin { user_id } => {
            if !state.users.contains_key(&user_id) { bail!("unknown user"); }
            let challenge = random_challenge();
            *auth = ConnAuth::Pending { user_id, challenge: challenge.clone() };
            out_tx.send(ServerMessage::AuthChallenge { nonce: b64(&challenge) })?;
        }

        AuthFinish { signature } => {
            let ConnAuth::Pending { user_id, challenge } = auth else {
                bail!("no pending auth — call auth_begin first");
            };
            let user_id   = *user_id;
            let challenge = challenge.clone();
            let sig_bytes = B64.decode(&signature).context("signature not base64")?;
            let user      = state.users.get(&user_id).ok_or_else(|| anyhow!("unknown user"))?;
            verify_dilithium_signature(&user.sig_public_key, &challenge, &sig_bytes)?;
            drop(user);

            // Promote.
            state.online.insert(user_id, Session { user_id, tx: out_tx.clone() });
            *auth = ConnAuth::Auth { user_id };
            out_tx.send(ServerMessage::Authenticated { user_id })?;
        }

        // -------- channel lifecycle ---------------------------------------
        CreateServer { name } => {
            let me = require_auth!();
            let server_id = Uuid::new_v4();
            let mut channels = state.channels.write().await;
            channels.insert(server_id, ChannelRecord {
                server_id,
                name,
                owner_id: me,
                members: HashSet::from([me]),
                epoch:    0,
                history:  Vec::new(),
            });
            out_tx.send(ServerMessage::ServerCreated { server_id, epoch: 0 })?;
        }

        JoinServer { server_id } => {
            let me = require_auth!();

            // Phase 1: mutate membership & gather info we need to broadcast.
            let (members_snapshot, new_epoch) = {
                let mut channels = state.channels.write().await;
                let ch = channels.get_mut(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
                if !ch.members.insert(me) {
                    bail!("already a member");
                }
                ch.epoch += 1;
                (ch.members.clone(), ch.epoch)
            };

            // Phase 2: assemble member infos for the joiner.
            let infos: Vec<MemberInfo> = members_snapshot.iter().filter_map(|uid| {
                state.users.get(uid).map(|u| MemberInfo {
                    user_id:        u.user_id,
                    display_name:   u.display_name.clone(),
                    kem_public_key: u.kem_public_key.clone(),
                    sig_public_key: u.sig_public_key.clone(),
                })
            }).collect();

            // Tell joiner who's in the room.
            out_tx.send(ServerMessage::ServerJoined {
                server_id, epoch: new_epoch, members: infos,
            })?;

            // Tell everyone else (including offline-buffered? no, online only)
            // that a new member appeared, so they can rekey.
            if let Some(joiner) = state.users.get(&me) {
                let info = MemberInfo {
                    user_id:        joiner.user_id,
                    display_name:   joiner.display_name.clone(),
                    kem_public_key: joiner.kem_public_key.clone(),
                    sig_public_key: joiner.sig_public_key.clone(),
                };
                let notice = ServerMessage::MemberJoined {
                    server_id, member: info, epoch: new_epoch,
                };
                state.broadcast(server_id, Some(me), notice).await;
            }
        }

        LeaveServer { server_id } => {
            let me = require_auth!();
            let new_epoch = {
                let mut channels = state.channels.write().await;
                let ch = channels.get_mut(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
                if !ch.members.remove(&me) { bail!("not a member"); }
                ch.epoch += 1;
                ch.epoch
            };
            out_tx.send(ServerMessage::ServerLeft { server_id })?;
            state.broadcast(
                server_id, Some(me),
                ServerMessage::MemberLeft { server_id, user_id: me, epoch: new_epoch },
            ).await;
        }

        // -------- key distribution ----------------------------------------
        DistributeKey { server_id, target_user_id, epoch, wrapped_key } => {
            let me = require_auth!();
            // Verify the sender is in the channel and the recipient is too.
            {
                let channels = state.channels.read().await;
                let ch = channels.get(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
                if !ch.members.contains(&me)              { bail!("you are not in this server"); }
                if !ch.members.contains(&target_user_id)  { bail!("target is not in this server"); }
            }
            let _ = B64.decode(&wrapped_key).context("wrapped_key not base64")?;
            // Forward verbatim. Server cannot inspect this — it's a Kyber
            // ciphertext only the target's secret key can open.
            state.push(target_user_id, ServerMessage::KeyMaterial {
                server_id, from_user: me, epoch, wrapped_key,
            });
        }

        // -------- messaging -----------------------------------------------
        SendMessage { server_id, epoch, nonce, ciphertext, signature } => {
            let me = require_auth!();
            let nonce_b   = B64.decode(&nonce).context("nonce not base64")?;
            let cipher_b  = B64.decode(&ciphertext).context("ciphertext not base64")?;
            let sig_b     = B64.decode(&signature).context("signature not base64")?;

            // Verify membership and current epoch.
            {
                let channels = state.channels.read().await;
                let ch = channels.get(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
                if !ch.members.contains(&me) { bail!("you are not in this server"); }
                if ch.epoch != epoch {
                    bail!("stale epoch (expected {}, got {})", ch.epoch, epoch);
                }
            }

            // Optional: verify the sender's signature over the message.
            // The "signed payload" is server_id || epoch || nonce || ciphertext.
            let mut signed = Vec::with_capacity(16 + 8 + nonce_b.len() + cipher_b.len());
            signed.extend_from_slice(server_id.as_bytes());
            signed.extend_from_slice(&epoch.to_le_bytes());
            signed.extend_from_slice(&nonce_b);
            signed.extend_from_slice(&cipher_b);
            if let Some(user) = state.users.get(&me) {
                verify_dilithium_signature(&user.sig_public_key, &signed, &sig_b)
                    .context("message signature invalid")?;
            }

            let stored = StoredMessage {
                message_id: Uuid::new_v4(),
                sender:     me,
                epoch,
                nonce:      nonce_b,
                ciphertext: cipher_b,
                signature:  sig_b,
                timestamp:  Utc::now(),
            };

            // Persist into ring buffer.
            {
                let mut channels = state.channels.write().await;
                let ch = channels.get_mut(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
                ch.history.push(stored.clone());
                let overflow = ch.history.len().saturating_sub(MAX_HISTORY);
                if overflow > 0 { ch.history.drain(0..overflow); }
            }

            // Fan out.
            let frame = ServerMessage::NewMessage {
                server_id,
                message_id: stored.message_id,
                sender:     stored.sender,
                epoch:      stored.epoch,
                nonce:      b64(&stored.nonce),
                ciphertext: b64(&stored.ciphertext),
                signature:  b64(&stored.signature),
                timestamp:  stored.timestamp,
            };
            state.broadcast(server_id, None, frame).await;
        }

        // -------- queries -------------------------------------------------
        ListServers => {
            let _me = require_auth!();
            let channels = state.channels.read().await;
            let servers = channels.values().map(|c| ServerInfo {
                server_id:    c.server_id,
                name:         c.name.clone(),
                owner_id:     c.owner_id,
                member_count: c.members.len(),
            }).collect();
            out_tx.send(ServerMessage::ServerList { servers })?;
        }

        ListMembers { server_id } => {
            let me = require_auth!();
            let channels = state.channels.read().await;
            let ch = channels.get(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
            if !ch.members.contains(&me) { bail!("not a member"); }
            let members: Vec<MemberInfo> = ch.members.iter().filter_map(|uid| {
                state.users.get(uid).map(|u| MemberInfo {
                    user_id:        u.user_id,
                    display_name:   u.display_name.clone(),
                    kem_public_key: u.kem_public_key.clone(),
                    sig_public_key: u.sig_public_key.clone(),
                })
            }).collect();
            out_tx.send(ServerMessage::MemberList { server_id, members })?;
        }

        GetHistory { server_id } => {
            let me = require_auth!();
            let channels = state.channels.read().await;
            let ch = channels.get(&server_id).ok_or_else(|| anyhow!("unknown server"))?;
            if !ch.members.contains(&me) { bail!("not a member"); }
            out_tx.send(ServerMessage::History {
                server_id,
                messages: ch.history.clone(),
            })?;
        }

        LookupUser { user_id } => {
            let _me = require_auth!();
            let user = state.users.get(&user_id).ok_or_else(|| anyhow!("unknown user"))?;
            out_tx.send(ServerMessage::UserInfo { user: user.clone() })?;
        }
    }

    Ok(())
}

// ============================================================================
// main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    let state    = AppState::new();
    let listener = TcpListener::bind(BIND_ADDR).await
        .with_context(|| format!("binding {BIND_ADDR}"))?;
    tracing::info!("pq-chat backend listening on ws://{BIND_ADDR}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream, peer).await {
                tracing::warn!(%peer, "connection ended with error: {e:#}");
            }
        });
    }
}

// ============================================================================
// Tests — minimal sanity checks for the crypto verification path.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::SecretKey as _;

    #[test]
    fn dilithium_round_trip() {
        let (pk, sk) = dilithium3::keypair();
        let msg = b"challenge bytes";
        let sig = dilithium3::detached_sign(msg, &sk);

        verify_dilithium_signature(pk.as_bytes(), msg, sig.as_bytes())
            .expect("valid signature must verify");

        // Tampered message must fail.
        let bad = b"different bytes";
        assert!(verify_dilithium_signature(pk.as_bytes(), bad, sig.as_bytes()).is_err());

        // Tampered signature must fail.
        let mut bad_sig = sig.as_bytes().to_vec();
        bad_sig[0] ^= 0xFF;
        assert!(verify_dilithium_signature(pk.as_bytes(), msg, &bad_sig).is_err());

        // sk only used to make the compiler accept the unused binding.
        let _ = sk.as_bytes();
    }

    #[test]
    fn kyber_pubkey_validation() {
        let (pk, _sk) = kyber768::keypair();
        validate_kyber_pubkey(pk.as_bytes()).expect("real pubkey is valid");
        assert!(validate_kyber_pubkey(b"too short").is_err());
    }
}
