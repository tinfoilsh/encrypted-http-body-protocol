use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

use crate::{
    protocol::{
        AES256_KEY_LENGTH, AES_GCM_NONCE_LENGTH, EXPORT_LENGTH, REQUEST_ENC_LENGTH,
        RESPONSE_KEY_LABEL, RESPONSE_NONCE_LABEL, RESPONSE_NONCE_LENGTH,
    },
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct ResponseKeyMaterial {
    pub key: [u8; AES256_KEY_LENGTH],
    pub nonce_base: [u8; AES_GCM_NONCE_LENGTH],
}

impl fmt::Debug for ResponseKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseKeyMaterial")
            .field("key", &"[redacted]")
            .field("nonce_base", &"[redacted]")
            .finish()
    }
}

impl Drop for ResponseKeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce_base.zeroize();
    }
}

pub fn derive_response_keys(
    exported_secret: &[u8],
    request_enc: &[u8],
    response_nonce: &[u8],
) -> Result<ResponseKeyMaterial> {
    if exported_secret.len() != EXPORT_LENGTH {
        return Err(Error::InvalidInput(format!(
            "exported secret must be {EXPORT_LENGTH} bytes, got {}",
            exported_secret.len()
        )));
    }
    if request_enc.len() != REQUEST_ENC_LENGTH {
        return Err(Error::InvalidInput(format!(
            "request enc must be {REQUEST_ENC_LENGTH} bytes, got {}",
            request_enc.len()
        )));
    }
    if response_nonce.len() != RESPONSE_NONCE_LENGTH {
        return Err(Error::InvalidInput(format!(
            "response nonce must be {RESPONSE_NONCE_LENGTH} bytes, got {}",
            response_nonce.len()
        )));
    }

    let mut salt = Vec::with_capacity(request_enc.len() + response_nonce.len());
    salt.extend_from_slice(request_enc);
    salt.extend_from_slice(response_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), exported_secret);
    let mut key = [0u8; AES256_KEY_LENGTH];
    let mut nonce_base = [0u8; AES_GCM_NONCE_LENGTH];
    hk.expand(RESPONSE_KEY_LABEL, &mut key)
        .map_err(|err| Error::Crypto(format!("failed to derive response key: {err}")))?;
    hk.expand(RESPONSE_NONCE_LABEL, &mut nonce_base)
        .map_err(|err| Error::Crypto(format!("failed to derive response nonce: {err}")))?;

    Ok(ResponseKeyMaterial { key, nonce_base })
}

pub fn compute_nonce(
    nonce_base: &[u8; AES_GCM_NONCE_LENGTH],
    seq: u64,
) -> [u8; AES_GCM_NONCE_LENGTH] {
    let mut nonce = *nonce_base;
    for i in 0..8 {
        nonce[AES_GCM_NONCE_LENGTH - 1 - i] ^= (seq >> (i * 8)) as u8;
    }
    nonce
}

pub(crate) fn decrypt_chunk(
    key_material: &ResponseKeyMaterial,
    seq: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key_material.key)
        .map_err(|err| Error::Crypto(format!("failed to create AES-GCM cipher: {err}")))?;
    let nonce = compute_nonce(&key_material.nonce_base, seq);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|err| Error::Crypto(format!("failed to decrypt chunk: {err}")))
}

pub(crate) fn decrypt_framed_response(
    key_material: &ResponseKeyMaterial,
    body: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut seq = 0u64;

    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(Error::Protocol("truncated chunk length".into()));
        }

        let chunk_len = u32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ]) as usize;
        offset += 4;

        if chunk_len == 0 {
            continue;
        }
        if body.len() - offset < chunk_len {
            return Err(Error::Protocol("truncated encrypted chunk".into()));
        }

        let plaintext = decrypt_chunk(key_material, seq, &body[offset..offset + chunk_len])?;
        out.extend_from_slice(&plaintext);
        seq = seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("response chunk sequence overflow".into()))?;
        offset += chunk_len;
    }

    Ok(out)
}

pub(crate) fn frame_chunk(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(ciphertext.len())
        .map_err(|_| Error::InvalidInput("ciphertext chunk is too large".into()))?;
    let mut framed = Vec::with_capacity(4 + ciphertext.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(ciphertext);
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_uses_big_endian_sequence_xor() {
        let base = [0u8; AES_GCM_NONCE_LENGTH];
        let nonce = compute_nonce(&base, 0x0102_0304_0506_0708);
        assert_eq!(nonce, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn debug_redacts_response_key_material() {
        let key_material = ResponseKeyMaterial {
            key: [1; AES256_KEY_LENGTH],
            nonce_base: [2; AES_GCM_NONCE_LENGTH],
        };
        let debug = format!("{key_material:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("1, 1"));
        assert!(!debug.contains("2, 2"));
    }
}
