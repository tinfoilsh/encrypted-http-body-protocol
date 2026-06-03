use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    derive::{decrypt_framed_response, derive_response_keys},
    protocol::{EXPORT_LENGTH, REQUEST_ENC_LENGTH, RESPONSE_NONCE_LENGTH},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct SessionRecoveryToken {
    pub exported_secret: Vec<u8>,
    pub request_enc: Vec<u8>,
}

struct SensitiveString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl fmt::Debug for SessionRecoveryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecoveryToken")
            .field("exported_secret", &"[redacted]")
            .field("request_enc", &"[redacted]")
            .finish()
    }
}

impl Drop for SessionRecoveryToken {
    fn drop(&mut self) {
        self.exported_secret.zeroize();
        self.request_enc.zeroize();
    }
}

impl SessionRecoveryToken {
    pub fn new(exported_secret: Vec<u8>, request_enc: Vec<u8>) -> Result<Self> {
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
        Ok(Self {
            exported_secret,
            request_enc,
        })
    }

    pub fn decrypt_response_body(&self, response_nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        if response_nonce.len() != RESPONSE_NONCE_LENGTH {
            return Err(Error::Protocol(format!(
                "response nonce must be {RESPONSE_NONCE_LENGTH} bytes, got {}",
                response_nonce.len()
            )));
        }
        let key_material =
            derive_response_keys(&self.exported_secret, &self.request_enc, response_nonce)?;
        decrypt_framed_response(&key_material, body)
    }
}

impl Serialize for SessionRecoveryToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Token<'a> {
            #[serde(rename = "exportedSecret")]
            exported_secret: &'a str,
            #[serde(rename = "requestEnc")]
            request_enc: &'a str,
        }

        let exported_secret = Zeroizing::new(hex::encode(&self.exported_secret));
        let request_enc = Zeroizing::new(hex::encode(&self.request_enc));
        Token {
            exported_secret: &exported_secret,
            request_enc: &request_enc,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SessionRecoveryToken {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Token {
            #[serde(rename = "exportedSecret")]
            exported_secret: SensitiveString,
            #[serde(rename = "requestEnc")]
            request_enc: SensitiveString,
        }

        let token = Token::deserialize(deserializer)?;
        let exported_secret = Zeroizing::new(
            hex::decode(token.exported_secret.0.as_bytes()).map_err(serde::de::Error::custom)?,
        );
        let request_enc = Zeroizing::new(
            hex::decode(token.request_enc.0.as_bytes()).map_err(serde::de::Error::custom)?,
        );
        if exported_secret.len() != EXPORT_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "exported secret must be {EXPORT_LENGTH} bytes, got {}",
                exported_secret.len()
            )));
        }
        if request_enc.len() != REQUEST_ENC_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "request enc must be {REQUEST_ENC_LENGTH} bytes, got {}",
                request_enc.len()
            )));
        }
        Ok(Self {
            exported_secret: exported_secret.to_vec(),
            request_enc: request_enc.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_session_recovery_token_material() {
        let token = SessionRecoveryToken::new(vec![1; 32], vec![2; 32]).unwrap();
        let debug = format!("{token:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("1, 1"));
        assert!(!debug.contains("2, 2"));
    }
}
