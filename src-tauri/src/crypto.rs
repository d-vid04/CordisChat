//! Client-side crypto.
//!
//! The server is a relay and never sees any of this — it only verifies
//! Dilithium signatures over the auth challenge and over message frames
//! (using public keys we uploaded at registration). Everything else lives
//! here.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};
use rand::RngCore;

/// 32-byte AES-256 group key.
pub type GroupKey = [u8; 32];

// ----------------------------------------------------------------------------
// Keypair generation
// ----------------------------------------------------------------------------

pub fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber768::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn generate_dilithium_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium3::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn random_group_key() -> GroupKey {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

// ----------------------------------------------------------------------------
// Dilithium3 signatures
// ----------------------------------------------------------------------------

pub fn dilithium_sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium3::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| anyhow!("invalid Dilithium3 secret key: {e:?}"))?;
    let sig = dilithium3::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn dilithium_verify(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let pk = dilithium3::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| anyhow!("invalid Dilithium3 public key: {e:?}"))?;
    let sig = dilithium3::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|e| anyhow!("invalid Dilithium3 signature: {e:?}"))?;
    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| anyhow!("Dilithium3 signature verification failed"))
}

// ----------------------------------------------------------------------------
// Kyber768 KEM — wrap & unwrap a 32-byte group key
// ----------------------------------------------------------------------------
//
// The `pqcrypto-kyber` API doesn't let us encapsulate an arbitrary chosen
// secret directly — `encapsulate` derives the shared secret from its own
// randomness. So to ship a *chosen* group key to a recipient, we:
//   1. Run KEM encapsulate against their pubkey → (kem_ct, kem_ss).
//   2. XOR the group key with the first 32 bytes of kem_ss → masked_key.
//   3. Wrapped envelope = kem_ct || masked_key. (Recipient does the inverse.)
//
// This is a standard "KEM-DEM" pattern with a one-time pad DEM because the
// payload is exactly the KEM-derived key length. Authenticity comes from
// the Dilithium signature on each message frame (the relay still has to
// believe in the sender's identity), and from the fact that only the
// holder of the recipient's Kyber secret key can decapsulate.

pub fn wrap_group_key_for(recipient_kem_pk: &[u8], group_key: &GroupKey) -> Result<Vec<u8>> {
    let pk = kyber768::PublicKey::from_bytes(recipient_kem_pk)
        .map_err(|e| anyhow!("invalid recipient Kyber pubkey: {e:?}"))?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    let ss_bytes = ss.as_bytes();
    if ss_bytes.len() < 32 {
        return Err(anyhow!("kyber shared secret unexpectedly short"));
    }
    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = group_key[i] ^ ss_bytes[i];
    }
    let mut out = Vec::with_capacity(ct.as_bytes().len() + 32);
    out.extend_from_slice(ct.as_bytes());
    out.extend_from_slice(&masked);
    Ok(out)
}

pub fn unwrap_group_key(my_kem_sk: &[u8], envelope: &[u8]) -> Result<GroupKey> {
    let ct_len = kyber768::ciphertext_bytes();
    if envelope.len() != ct_len + 32 {
        return Err(anyhow!(
            "wrapped envelope wrong size: got {}, expected {}",
            envelope.len(),
            ct_len + 32
        ));
    }
    let sk = kyber768::SecretKey::from_bytes(my_kem_sk)
        .map_err(|e| anyhow!("invalid Kyber secret key: {e:?}"))?;
    let ct = kyber768::Ciphertext::from_bytes(&envelope[..ct_len])
        .map_err(|e| anyhow!("invalid Kyber ciphertext: {e:?}"))?;
    let ss = kyber768::decapsulate(&ct, &sk);
    let ss_bytes = ss.as_bytes();
    let masked = &envelope[ct_len..];
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = masked[i] ^ ss_bytes[i];
    }
    Ok(key)
}

// ----------------------------------------------------------------------------
// AES-256-GCM seal / open
// ----------------------------------------------------------------------------

pub fn aes_seal(key: &GroupKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce  = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("AES-GCM seal failed: {e}"))?;
    Ok((nonce.to_vec(), ct))
}

pub fn aes_open(key: &GroupKey, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(anyhow!("AES-GCM nonce must be 12 bytes, got {}", nonce.len()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let n = Nonce::from_slice(nonce);
    cipher
        .decrypt(n, ciphertext)
        .map_err(|e| anyhow!("AES-GCM open failed: {e}"))
}

// ----------------------------------------------------------------------------
// Signed-message payload helper — must match the server's signed bytes layout
// exactly. See main.rs in the backend: server_id || epoch.to_le_bytes() ||
// nonce || ciphertext.
// ----------------------------------------------------------------------------

pub fn message_signed_payload(
    server_id: &uuid::Uuid,
    epoch: u64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(16 + 8 + nonce.len() + ciphertext.len());
    signed.extend_from_slice(server_id.as_bytes());
    signed.extend_from_slice(&epoch.to_le_bytes());
    signed.extend_from_slice(nonce);
    signed.extend_from_slice(ciphertext);
    signed
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kyber_wrap_round_trip() -> Result<()> {
        let (pk, sk) = generate_kyber_keypair();
        let key      = random_group_key();
        let env      = wrap_group_key_for(&pk, &key)?;
        let recovered = unwrap_group_key(&sk, &env)?;
        assert_eq!(key, recovered);
        Ok(())
    }

    #[test]
    fn dilithium_round_trip() -> Result<()> {
        let (pk, sk) = generate_dilithium_keypair();
        let msg = b"hello quantum";
        let sig = dilithium_sign(&sk, msg)?;
        dilithium_verify(&pk, msg, &sig)?;
        Ok(())
    }

    #[test]
    fn aes_round_trip() -> Result<()> {
        let key = random_group_key();
        let (nonce, ct) = aes_seal(&key, b"top secret")?;
        let pt = aes_open(&key, &nonce, &ct)?;
        assert_eq!(pt, b"top secret");
        Ok(())
    }
}
