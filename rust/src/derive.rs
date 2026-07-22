use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use bytes::{Buf, BytesMut};
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

const DEFAULT_MAX_RESPONSE_CHUNK_BYTES: usize = 64 * 1024 * 1024;

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
    let mut decryptor = ResponseDecryptor::from_key_material(key_material.clone());
    let out = decryptor.push(body)?.concat();
    decryptor.finish()?;
    Ok(out)
}

/// Incrementally decrypts an EHBP framed response.
///
/// Feed encrypted network bytes with [`Self::push`] and call [`Self::finish`]
/// when the source reaches EOF. `push` returns each authenticated plaintext
/// frame as soon as it is complete, without waiting for source EOF.
pub struct ResponseDecryptor {
    key_material: ResponseKeyMaterial,
    buffer: BytesMut,
    sequence: u64,
    max_chunk_length: usize,
}

impl ResponseDecryptor {
    pub(crate) fn from_key_material(key_material: ResponseKeyMaterial) -> Self {
        Self {
            key_material,
            buffer: BytesMut::new(),
            sequence: 0,
            max_chunk_length: DEFAULT_MAX_RESPONSE_CHUNK_BYTES,
        }
    }

    /// Adds encrypted bytes and returns all newly authenticated plaintext frames.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.buffer.extend_from_slice(data);
        let mut plaintext = Vec::new();

        loop {
            if self.buffer.len() < 4 {
                break;
            }

            let chunk_len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            if chunk_len == 0 {
                self.buffer.advance(4);
                continue;
            }
            if chunk_len > self.max_chunk_length {
                return Err(Error::Protocol(
                    "response chunk exceeds maximum allowed size".into(),
                ));
            }
            if self.buffer.len() < 4 + chunk_len {
                break;
            }
            if self.sequence == u64::MAX {
                return Err(Error::Protocol("response chunk sequence overflow".into()));
            }

            self.buffer.advance(4);
            let ciphertext = self.buffer.split_to(chunk_len).freeze();
            let opened = decrypt_chunk(&self.key_material, self.sequence, &ciphertext)?;
            self.sequence += 1;
            plaintext.push(opened);
        }

        Ok(plaintext)
    }

    /// Validates that source EOF occurred on a frame boundary.
    pub fn finish(&self) -> Result<()> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("truncated encrypted response chunk".into()))
        }
    }
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

    fn key_material() -> ResponseKeyMaterial {
        ResponseKeyMaterial {
            key: [7; AES256_KEY_LENGTH],
            nonce_base: [9; AES_GCM_NONCE_LENGTH],
        }
    }

    fn encrypted_frame(key_material: &ResponseKeyMaterial, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&key_material.key).unwrap();
        let nonce = compute_nonce(&key_material.nonce_base, seq);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        frame_chunk(&ciphertext).unwrap()
    }

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

    #[test]
    fn response_decryptor_delivers_before_finish_and_handles_fragmentation() {
        let key_material = key_material();
        let first = encrypted_frame(&key_material, 0, b"first");
        let second = encrypted_frame(&key_material, 1, b"second");
        let mut decryptor = ResponseDecryptor::from_key_material(key_material);

        assert!(decryptor.push(&first[..3]).unwrap().is_empty());
        assert_eq!(decryptor.push(&first[3..]).unwrap(), [b"first".to_vec()]);

        let mut coalesced = vec![0, 0, 0, 0];
        coalesced.extend_from_slice(&second);
        coalesced.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decryptor.push(&coalesced).unwrap(), [b"second".to_vec()]);
        decryptor.finish().unwrap();
    }

    #[test]
    fn response_decryptor_rejects_truncation_and_authentication_failure() {
        let key_material = key_material();
        let frame = encrypted_frame(&key_material, 0, b"secret");
        let mut truncated = ResponseDecryptor::from_key_material(key_material.clone());
        assert!(truncated
            .push(&frame[..frame.len() - 1])
            .unwrap()
            .is_empty());
        assert!(matches!(truncated.finish(), Err(Error::Protocol(_))));

        let mut tampered_frame = frame;
        *tampered_frame.last_mut().unwrap() ^= 1;
        let mut tampered = ResponseDecryptor::from_key_material(key_material);
        assert!(matches!(
            tampered.push(&tampered_frame),
            Err(Error::Crypto(_))
        ));
    }

    #[test]
    fn response_decryptor_enforces_size_and_sequence_limits() {
        let mut oversized = ResponseDecryptor::from_key_material(key_material());
        let oversized_prefix = u32::MAX.to_be_bytes();
        assert!(matches!(
            oversized.push(&oversized_prefix),
            Err(Error::Protocol(message)) if message.contains("maximum allowed size")
        ));

        let mut exhausted = ResponseDecryptor::from_key_material(key_material());
        exhausted.sequence = u64::MAX;
        let frame = frame_chunk(&[0; 16]).unwrap();
        assert!(matches!(
            exhausted.push(&frame),
            Err(Error::Protocol(message)) if message.contains("sequence overflow")
        ));
    }
}
