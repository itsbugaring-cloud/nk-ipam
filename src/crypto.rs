use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

use crate::app_error::{AppError, AppResult};

fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

pub fn encrypt(secret: &str, plaintext: &str) -> AppResult<String> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| AppError::Internal(format!("cipher init failed: {err}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|err| AppError::Internal(format!("encryption failed: {err}")))?;

    let mut payload = nonce_bytes.to_vec();
    payload.extend(ciphertext);
    Ok(STANDARD.encode(payload))
}

pub fn decrypt(secret: &str, encoded: &str) -> AppResult<String> {
    let payload = STANDARD
        .decode(encoded)
        .map_err(|err| AppError::Internal(format!("base64 decode failed: {err}")))?;

    if payload.len() < 13 {
        return Err(AppError::Internal("encrypted payload too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| AppError::Internal(format!("cipher init failed: {err}")))?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|err| AppError::Internal(format!("decryption failed: {err}")))?;

    String::from_utf8(plaintext)
        .map_err(|err| AppError::Internal(format!("utf8 decode failed: {err}")))
}
