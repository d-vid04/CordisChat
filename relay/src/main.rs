//! Minimal in-memory relay for the pq-chat client.
//!
//! "Dumb fan-out" exactly as the client's README describes: it stores public
//! keys + ciphertext, tracks channel membership and epochs, and forwards
//! frames. It never sees a private key, a group key, or a plaintext.
//!
//! Scope / simplifications (this is a dev & integration-test relay, not a
//! production server):
//!   * `AuthFinish` is accepted without verifying the Dilithium signature
//!     over the challenge. A real relay would verify `signature` against the
//!     registered `sig_public_key`. The challenge is still issued so the
//!     client's full auth round-trip is exercised.
//!   * All state is in memory (`HashMap`), so a restart wipes users — which
//!     is the exact condition the client's "unknown user" re-registration
//!     path handles.
//!
//! Run:  cargo run            (listens on ws://127.0.0.1:8080)
//!       cargo run 0.0.0.0:9000

mod protocol;

use protocol::*;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message as Ws;
use uuid::Uuid;

/// Per-connection outbound queue. The reader loop and any fan-out push JSON
/// strings here; a dedicated writer task drains them onto the socket.
type Tx = mpsc::UnboundedSender<String>;

struct Channel {
    name:     String,
    owner_id: UserId,
    epoch:    Epoch,
    members:  HashSet<UserId>,
    messages: Vec<StoredMessage>,
}

#[derive(Default)]
struct Hub {
    users:    HashMap<UserId, UserRecord>,
    channels: HashMap<ServerId, Channel>,
    /// Currently-connected authenticated users → their outbound queue.
    online:   HashMap<UserId, Tx>,
}

type Shared = Arc<Mutex<Hub>>;

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let hub: Shared = Arc::new(Mutex::new(Hub::default()));
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    println!("pq-chat relay listening on ws://{addr}");

    while let Ok((stream, peer)) = listener.accept().await {
        let hub = hub.clone();
        tokio::spawn(async move {
            println!("connection from {peer}");
            handle_conn(stream, hub).await;
        });
    }
}

async fn handle_conn(stream: TcpStream, hub: Shared) {
    let ws = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("websocket handshake failed: {e}");
            return;
        }
    };
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Writer task: drain the outbound queue onto the socket.
    tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sink.send(Ws::Text(text)).await.is_err() {
                break;
            }
        }
    });

    // Connection-local auth state.
    let mut me: Option<UserId> = None;       // set once authenticated
    let mut pending: Option<UserId> = None;  // user_id mid-challenge

    while let Some(frame) = stream.next().await {
        let text = match frame {
            Ok(Ws::Text(t)) => t,
            Ok(Ws::Binary(b)) => String::from_utf8_lossy(&b).into_owned(),
            Ok(Ws::Close(_)) => break,
            Ok(_) => continue, // ping/pong/frame — tungstenite handles pings
            Err(_) => break,
        };
        let cm: ClientMessage = match serde_json::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                send(&tx, &ServerMessage::Error { reason: format!("bad frame: {e}") });
                continue;
            }
        };
        handle_msg(&hub, &tx, &mut me, &mut pending, cm).await;
    }

    if let Some(u) = me {
        hub.lock().await.online.remove(&u);
        println!("user {u} disconnected");
    }
}

async fn handle_msg(
    hub: &Shared,
    tx: &Tx,
    me: &mut Option<UserId>,
    pending: &mut Option<UserId>,
    cm: ClientMessage,
) {
    match cm {
        // --- Registration & auth ------------------------------------------
        ClientMessage::Register { display_name, kem_public_key, sig_public_key } => {
            let user_id = Uuid::new_v4();
            let rec = UserRecord {
                user_id,
                display_name: display_name.clone(),
                kem_public_key: B64.decode(&kem_public_key).unwrap_or_default(),
                sig_public_key: B64.decode(&sig_public_key).unwrap_or_default(),
                created_at: Utc::now(),
            };
            hub.lock().await.users.insert(user_id, rec);
            println!("registered {display_name} as {user_id}");
            send(tx, &ServerMessage::Registered { user_id });
        }

        ClientMessage::AuthBegin { user_id } => {
            if !hub.lock().await.users.contains_key(&user_id) {
                send(tx, &ServerMessage::Error { reason: "unknown user".into() });
                return;
            }
            // Issue a random challenge. (We don't verify the response — see
            // the module-level note — but the client signs & returns it.)
            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            *pending = Some(user_id);
            send(tx, &ServerMessage::AuthChallenge { nonce: B64.encode(nonce) });
        }

        ClientMessage::AuthFinish { signature: _ } => match pending.take() {
            Some(uid) => {
                *me = Some(uid);
                hub.lock().await.online.insert(uid, tx.clone());
                println!("user {uid} authenticated");
                send(tx, &ServerMessage::Authenticated { user_id: uid });
            }
            None => send(tx, &ServerMessage::Error { reason: "no auth in progress".into() }),
        },

        // --- Servers ------------------------------------------------------
        ClientMessage::CreateServer { name } => {
            let Some(uid) = *me else { return unauth(tx); };
            let server_id = Uuid::new_v4();
            hub.lock().await.channels.insert(server_id, Channel {
                name: name.clone(),
                owner_id: uid,
                epoch: 0,
                members: HashSet::from([uid]),
                messages: Vec::new(),
            });
            println!("user {uid} created server '{name}' {server_id}");
            send(tx, &ServerMessage::ServerCreated { server_id, epoch: 0 });
        }

        ClientMessage::JoinServer { server_id } => {
            let Some(uid) = *me else { return unauth(tx); };
            let mut h = hub.lock().await;

            let (epoch, member_ids) = {
                let Some(ch) = h.channels.get_mut(&server_id) else {
                    send(tx, &ServerMessage::Error { reason: "no such server".into() });
                    return;
                };
                ch.members.insert(uid);
                ch.epoch += 1; // a membership change bumps the epoch
                (ch.epoch, ch.members.iter().copied().collect::<Vec<_>>())
            };

            // Full roster for the joiner; the join notification for everyone else.
            let members: Vec<MemberInfo> =
                member_ids.iter().filter_map(|id| minfo(&h.users, id)).collect();
            send(tx, &ServerMessage::ServerJoined { server_id, epoch, members });

            if let Some(joiner) = minfo(&h.users, &uid) {
                for id in &member_ids {
                    if *id == uid {
                        continue;
                    }
                    if let Some(peer_tx) = h.online.get(id) {
                        send(peer_tx, &ServerMessage::MemberJoined {
                            server_id,
                            member: joiner.clone(),
                            epoch,
                        });
                    }
                }
            }
            println!("user {uid} joined {server_id} -> epoch {epoch}");
        }

        ClientMessage::LeaveServer { server_id } => {
            let Some(uid) = *me else { return unauth(tx); };
            let mut h = hub.lock().await;

            let (epoch, remaining) = {
                let Some(ch) = h.channels.get_mut(&server_id) else {
                    send(tx, &ServerMessage::Error { reason: "no such server".into() });
                    return;
                };
                ch.members.remove(&uid);
                ch.epoch += 1;
                (ch.epoch, ch.members.iter().copied().collect::<Vec<_>>())
            };

            send(tx, &ServerMessage::ServerLeft { server_id });
            for id in &remaining {
                if let Some(peer_tx) = h.online.get(id) {
                    send(peer_tx, &ServerMessage::MemberLeft { server_id, user_id: uid, epoch });
                }
            }
            println!("user {uid} left {server_id} -> epoch {epoch}");
        }

        // --- Key distribution (forward to the targeted member) ------------
        ClientMessage::DistributeKey { server_id, target_user_id, epoch, wrapped_key } => {
            let Some(uid) = *me else { return unauth(tx); };
            let h = hub.lock().await;
            if let Some(peer_tx) = h.online.get(&target_user_id) {
                send(peer_tx, &ServerMessage::KeyMaterial {
                    server_id,
                    from_user: uid,
                    epoch,
                    wrapped_key,
                });
            }
            // No reply: the client sends DistributeKey fire-and-forget.
        }

        // --- Messages (store + fan out to all members, incl. sender) ------
        ClientMessage::SendMessage { server_id, epoch, nonce, ciphertext, signature } => {
            let Some(uid) = *me else { return unauth(tx); };
            let mut h = hub.lock().await;

            let member_ids = {
                let Some(ch) = h.channels.get_mut(&server_id) else {
                    send(tx, &ServerMessage::Error { reason: "no such server".into() });
                    return;
                };
                if !ch.members.contains(&uid) {
                    send(tx, &ServerMessage::Error { reason: "not a member".into() });
                    return;
                }
                let stored = StoredMessage {
                    message_id: Uuid::new_v4(),
                    sender: uid,
                    epoch,
                    nonce: B64.decode(&nonce).unwrap_or_default(),
                    ciphertext: B64.decode(&ciphertext).unwrap_or_default(),
                    signature: B64.decode(&signature).unwrap_or_default(),
                    timestamp: Utc::now(),
                };
                let out = ServerMessage::NewMessage {
                    server_id,
                    message_id: stored.message_id,
                    sender: uid,
                    epoch,
                    nonce,
                    ciphertext,
                    signature,
                    timestamp: stored.timestamp,
                };
                ch.messages.push(stored);
                // Capture members before dropping the &mut borrow, carry `out`.
                let ids = ch.members.iter().copied().collect::<Vec<_>>();
                fan_out(&h.online, &ids, &out);
                ids
            };
            let _ = member_ids;
        }

        // --- Read-only queries --------------------------------------------
        ClientMessage::ListServers => {
            let h = hub.lock().await;
            let servers = h.channels.iter().map(|(id, ch)| ServerInfo {
                server_id: *id,
                name: ch.name.clone(),
                owner_id: ch.owner_id,
                member_count: ch.members.len(),
            }).collect();
            send(tx, &ServerMessage::ServerList { servers });
        }

        ClientMessage::ListMembers { server_id } => {
            let h = hub.lock().await;
            let Some(ch) = h.channels.get(&server_id) else {
                send(tx, &ServerMessage::Error { reason: "no such server".into() });
                return;
            };
            let ids: Vec<UserId> = ch.members.iter().copied().collect();
            let members = ids.iter().filter_map(|id| minfo(&h.users, id)).collect();
            send(tx, &ServerMessage::MemberList { server_id, members });
        }

        ClientMessage::GetHistory { server_id } => {
            let h = hub.lock().await;
            let Some(ch) = h.channels.get(&server_id) else {
                send(tx, &ServerMessage::Error { reason: "no such server".into() });
                return;
            };
            send(tx, &ServerMessage::History { server_id, messages: ch.messages.clone() });
        }

        ClientMessage::LookupUser { user_id } => {
            let h = hub.lock().await;
            match h.users.get(&user_id) {
                Some(u) => send(tx, &ServerMessage::UserInfo { user: u.clone() }),
                None => send(tx, &ServerMessage::Error { reason: "unknown user".into() }),
            }
        }

        ClientMessage::Ping => send(tx, &ServerMessage::Pong),
    }
}

/// Serialise and enqueue a frame on one connection's outbound queue.
fn send(tx: &Tx, msg: &ServerMessage) {
    if let Ok(text) = serde_json::to_string(msg) {
        let _ = tx.send(text);
    }
}

/// Push the same frame to every listed member that is currently online.
fn fan_out(online: &HashMap<UserId, Tx>, members: &[UserId], msg: &ServerMessage) {
    for id in members {
        if let Some(tx) = online.get(id) {
            send(tx, msg);
        }
    }
}

/// Build a `MemberInfo` view of a registered user.
fn minfo(users: &HashMap<UserId, UserRecord>, id: &UserId) -> Option<MemberInfo> {
    users.get(id).map(|u| MemberInfo {
        user_id: u.user_id,
        display_name: u.display_name.clone(),
        kem_public_key: u.kem_public_key.clone(),
        sig_public_key: u.sig_public_key.clone(),
    })
}

fn unauth(tx: &Tx) {
    send(tx, &ServerMessage::Error { reason: "not authenticated".into() });
}
