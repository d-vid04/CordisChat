//! Persistent identity store.
//!
//! We persist the Kyber/Dilithium keypairs and the assigned user_id to a
//! JSON file in the OS application-data dir, so the user keeps the same
//! cryptographic identity across launches.
//!
//! **NOTE.** The private keys are stored unencrypted. For real use you would
//! key-wrap them under a password (Argon2id → AES-GCM) or hand them to the
//! OS keychain (Keychain on macOS, DPAPI on Windows, libsecret on Linux).
//! That is out of scope for this first cut — adding it later is a localised
//! change here.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub user_id:      Uuid,
    pub display_name: String,
    pub kem_pk_b64:   String,
    pub kem_sk_b64:   String,
    pub sig_pk_b64:   String,
    pub sig_sk_b64:   String,
}

impl Identity {
    pub fn kem_pk(&self) -> Result<Vec<u8>> { Ok(B64.decode(&self.kem_pk_b64)?) }
    pub fn kem_sk(&self) -> Result<Vec<u8>> { Ok(B64.decode(&self.kem_sk_b64)?) }
    pub fn sig_pk(&self) -> Result<Vec<u8>> { Ok(B64.decode(&self.sig_pk_b64)?) }
    pub fn sig_sk(&self) -> Result<Vec<u8>> { Ok(B64.decode(&self.sig_sk_b64)?) }
}

fn identity_path() -> Result<PathBuf> {
    // `PQ_CHAT_DATA_DIR` overrides the storage location. This lets you run
    // several clients side by side under distinct identities (useful for
    // testing multi-member channels / rekey): give each instance its own dir.
    let dir = if let Some(custom) = std::env::var_os("PQ_CHAT_DATA_DIR") {
        PathBuf::from(custom)
    } else {
        let dirs = ProjectDirs::from("dev", "pqchat", "pq-chat")
            .ok_or_else(|| anyhow::anyhow!("could not resolve app data dir"))?;
        dirs.data_dir().to_path_buf()
    };
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.join("identity.json"))
}

pub fn load() -> Result<Option<Identity>> {
    let path = identity_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let id: Identity = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(id))
}

pub fn save(id: &Identity) -> Result<()> {
    let path = identity_path()?;
    let bytes = serde_json::to_vec_pretty(id)?;
    // Best-effort atomic write: write to tmp, then rename.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| "renaming temp identity file")?;
    Ok(())
}

pub fn delete() -> Result<()> {
    let path = identity_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Create a new identity locally (no network). The user_id field is left as
/// nil-uuid; it gets filled in after the server `Registered` reply.
pub fn new_unregistered(display_name: String) -> Identity {
    let (kem_pk, kem_sk) = crate::crypto::generate_kyber_keypair();
    let (sig_pk, sig_sk) = crate::crypto::generate_dilithium_keypair();
    Identity {
        user_id:      Uuid::nil(),
        display_name,
        kem_pk_b64: B64.encode(&kem_pk),
        kem_sk_b64: B64.encode(&kem_sk),
        sig_pk_b64: B64.encode(&sig_pk),
        sig_sk_b64: B64.encode(&sig_sk),
    }
}
