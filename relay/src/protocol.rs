//! Wire protocol — copied verbatim from the client's `protocol.rs` so the
//! JSON shape is byte-for-byte identical on both ends. Do not "tidy" the
//! field types: `Vec<u8>` serialises as a JSON number array, while the
//! base64 `String` fields on `SendMessage`/`NewMessage` stay strings. The
//! client depends on exactly this split.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type UserId   = Uuid;
pub type ServerId = Uuid;
pub type Epoch    = u64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id:        UserId,
    pub display_name:   String,
    pub kem_public_key: Vec<u8>,
    pub sig_public_key: Vec<u8>,
    pub created_at:     DateTime<Utc>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub message_id: Uuid,
    pub sender:     UserId,
    pub epoch:      Epoch,
    pub nonce:      Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature:  Vec<u8>,
    pub timestamp:  DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Register {
        display_name:   String,
        kem_public_key: String,
        sig_public_key: String,
    },
    AuthBegin  { user_id: UserId },
    AuthFinish { signature: String },

    CreateServer { name: String },
    JoinServer   { server_id: ServerId },
    LeaveServer  { server_id: ServerId },

    DistributeKey {
        server_id:      ServerId,
        target_user_id: UserId,
        epoch:          Epoch,
        wrapped_key:    String,
    },

    SendMessage {
        server_id:  ServerId,
        epoch:      Epoch,
        nonce:      String,
        ciphertext: String,
        signature:  String,
    },

    ListServers,
    ListMembers { server_id: ServerId },
    GetHistory  { server_id: ServerId },
    LookupUser  { user_id: UserId },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Registered    { user_id: UserId },
    AuthChallenge { nonce: String },
    Authenticated { user_id: UserId },

    Error { reason: String },

    ServerCreated { server_id: ServerId, epoch: Epoch },
    ServerJoined  { server_id: ServerId, epoch: Epoch, members: Vec<MemberInfo> },
    ServerLeft    { server_id: ServerId },

    MemberJoined  { server_id: ServerId, member: MemberInfo, epoch: Epoch },
    MemberLeft    { server_id: ServerId, user_id: UserId,    epoch: Epoch },

    KeyMaterial {
        server_id:   ServerId,
        from_user:   UserId,
        epoch:       Epoch,
        wrapped_key: String,
    },

    NewMessage {
        server_id:  ServerId,
        message_id: Uuid,
        sender:     UserId,
        epoch:      Epoch,
        nonce:      String,
        ciphertext: String,
        signature:  String,
        timestamp:  DateTime<Utc>,
    },

    History    { server_id: ServerId, messages: Vec<StoredMessage> },
    ServerList { servers: Vec<ServerInfo> },
    MemberList { server_id: ServerId, members: Vec<MemberInfo> },
    UserInfo   { user: UserRecord },
    Pong,
}
