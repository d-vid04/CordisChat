//! In-memory client state. Wrapped in `Arc<RwLock<…>>` (per-field where it
//! makes sense) and shared between Tauri commands and the WS read loop.

use crate::crypto::GroupKey;
use crate::identity::Identity;
use crate::protocol::{Epoch, MemberInfo, ServerId, UserId};
use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc;

/// One entry per channel we're currently a member of.
#[derive(Default)]
pub struct ChannelView {
    /// All currently known members of this channel (cached locally so we can
    /// wrap keys for them without an extra LookupUser round-trip).
    pub members:    HashMap<UserId, MemberInfo>,
    /// Last epoch the server told us about.
    pub epoch:      Epoch,
    /// All group keys we hold for this channel, indexed by epoch. Old keys
    /// stay so we can decrypt history entries from the same session.
    pub keys:       BTreeMap<Epoch, GroupKey>,
    /// Human-readable channel name, cached.
    pub name:       String,
}

pub struct ClientState {
    pub identity: Option<Identity>,
    pub channels: HashMap<ServerId, ChannelView>,
    /// Outbound side of the WS — set when connected, cleared on disconnect.
    pub tx_out:   Option<mpsc::UnboundedSender<String>>,
    /// Currently in-flight RPC — exactly one at a time. The read loop sends
    /// the matching reply through this oneshot.
    pub pending_rpc: Option<tokio::sync::oneshot::Sender<crate::protocol::ServerMessage>>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            identity:    None,
            channels:    HashMap::new(),
            tx_out:      None,
            pending_rpc: None,
        }
    }

    pub fn require_identity(&self) -> anyhow::Result<&Identity> {
        self.identity.as_ref().ok_or_else(|| anyhow::anyhow!("no identity loaded"))
    }
}
