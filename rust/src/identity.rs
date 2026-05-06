use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    setup_sender, Deserializable, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    derive::frame_chunk,
    protocol::{
        AEAD_AES_256_GCM, EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO, KDF_HKDF_SHA256,
        KEM_X25519_HKDF_SHA256, KEY_ID, REQUEST_ENC_LENGTH,
    },
    session::SessionRecoveryToken,
    Error, Result,
};

type Aead = AesGcm256;
type Kdf = HkdfSha256;
type KemSuite = X25519HkdfSha256;
type PublicKey = <KemSuite as Kem>::PublicKey;

#[derive(Clone, Debug)]
pub struct ServerIdentity {
    key_id: u8,
    public_key: PublicKey,
}

impl ServerIdentity {
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != REQUEST_ENC_LENGTH {
            return Err(Error::InvalidConfig(format!(
                "public key must be {REQUEST_ENC_LENGTH} bytes, got {}",
                public_key.len()
            )));
        }
        let public_key = PublicKey::from_bytes(public_key)
            .map_err(|err| Error::InvalidConfig(format!("invalid X25519 public key: {err:?}")))?;
        Ok(Self {
            key_id: KEY_ID,
            public_key,
        })
    }

    pub fn from_public_key_hex(public_key_hex: &str) -> Result<Self> {
        let public_key = hex::decode(public_key_hex)?;
        Self::from_public_key_bytes(&public_key)
    }

    pub fn unmarshal_public_config(data: &[u8]) -> Result<Self> {
        let mut offset = 0usize;

        let key_id = *data
            .get(offset)
            .ok_or_else(|| Error::InvalidConfig("missing key id".into()))?;
        offset += 1;

        let kem_id = read_u16(data, &mut offset, "KEM id")?;
        if kem_id != KEM_X25519_HKDF_SHA256 {
            return Err(Error::InvalidConfig(format!(
                "unsupported KEM: 0x{kem_id:04x}"
            )));
        }

        let public_key_end = offset
            .checked_add(REQUEST_ENC_LENGTH)
            .ok_or_else(|| Error::InvalidConfig("public key offset overflow".into()))?;
        if public_key_end > data.len() {
            return Err(Error::InvalidConfig("truncated public key".into()));
        }
        let public_key_bytes = &data[offset..public_key_end];
        offset = public_key_end;

        let suites_len = read_u16(data, &mut offset, "cipher suites length")? as usize;
        if suites_len == 0 {
            return Err(Error::InvalidConfig(
                "no cipher suites found in config".into(),
            ));
        }
        if suites_len % 4 != 0 {
            return Err(Error::InvalidConfig(
                "cipher suites length must be a multiple of 4".into(),
            ));
        }
        let suites_end = offset
            .checked_add(suites_len)
            .ok_or_else(|| Error::InvalidConfig("cipher suites offset overflow".into()))?;
        if suites_end > data.len() {
            return Err(Error::InvalidConfig("truncated cipher suites".into()));
        }

        let kdf_id = read_u16(data, &mut offset, "KDF id")?;
        let aead_id = read_u16(data, &mut offset, "AEAD id")?;
        if kdf_id != KDF_HKDF_SHA256 || aead_id != AEAD_AES_256_GCM {
            return Err(Error::InvalidConfig(format!(
                "unsupported cipher suite: KDF=0x{kdf_id:04x}, AEAD=0x{aead_id:04x}"
            )));
        }

        let mut identity = Self::from_public_key_bytes(public_key_bytes)?;
        identity.key_id = key_id;
        Ok(identity)
    }

    pub fn marshal_public_config(&self) -> Vec<u8> {
        let public_key = self.public_key_bytes();
        let mut out = Vec::with_capacity(1 + 2 + public_key.len() + 2 + 4);
        out.push(self.key_id);
        out.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
        out.extend_from_slice(&public_key);
        out.extend_from_slice(&(4u16).to_be_bytes());
        out.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
        out.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());
        out
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub(crate) fn encrypt_request_body(
        &self,
        plaintext: &[u8],
    ) -> Result<Option<EncryptedRequest>> {
        if plaintext.is_empty() {
            return Ok(None);
        }

        let mut csprng = StdRng::from_os_rng();
        let (enc, mut sender) = setup_sender::<Aead, Kdf, KemSuite, _>(
            &OpModeS::Base,
            &self.public_key,
            HPKE_REQUEST_INFO,
            &mut csprng,
        )
        .map_err(|err| Error::Hpke(format!("failed to set up sender: {err:?}")))?;

        let ciphertext = sender
            .seal(plaintext, &[])
            .map_err(|err| Error::Hpke(format!("failed to seal request body: {err:?}")))?;
        let body = frame_chunk(&ciphertext)?;

        let mut exported_secret = vec![0u8; EXPORT_LENGTH];
        sender
            .export(EXPORT_LABEL, &mut exported_secret)
            .map_err(|err| Error::Hpke(format!("failed to export response secret: {err:?}")))?;

        let request_enc = enc.to_bytes().to_vec();
        let token = SessionRecoveryToken::new(exported_secret, request_enc.clone())?;

        Ok(Some(EncryptedRequest {
            encapsulated_key: request_enc,
            body,
            token,
        }))
    }
}

pub(crate) struct EncryptedRequest {
    pub encapsulated_key: Vec<u8>,
    pub body: Vec<u8>,
    pub token: SessionRecoveryToken,
}

fn read_u16(data: &[u8], offset: &mut usize, field: &str) -> Result<u16> {
    if data.len().saturating_sub(*offset) < 2 {
        return Err(Error::InvalidConfig(format!("missing {field}")));
    }
    let value = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{setup_receiver, OpModeR};

    #[test]
    fn encrypts_request_body_for_hpke_receiver() {
        let mut csprng = StdRng::from_os_rng();
        let (private_key, public_key) = KemSuite::gen_keypair(&mut csprng);
        let identity = ServerIdentity {
            key_id: KEY_ID,
            public_key,
        };

        let encrypted = identity
            .encrypt_request_body(b"hello rust")
            .unwrap()
            .expect("non-empty bodies are encrypted");

        let encapped_key =
            <KemSuite as Kem>::EncappedKey::from_bytes(&encrypted.encapsulated_key).unwrap();
        let mut receiver = setup_receiver::<Aead, Kdf, KemSuite>(
            &OpModeR::Base,
            &private_key,
            &encapped_key,
            HPKE_REQUEST_INFO,
        )
        .unwrap();

        let chunk_len = u32::from_be_bytes([
            encrypted.body[0],
            encrypted.body[1],
            encrypted.body[2],
            encrypted.body[3],
        ]) as usize;
        let plaintext = receiver
            .open(&encrypted.body[4..4 + chunk_len], &[])
            .unwrap();

        let mut exported_secret = vec![0u8; EXPORT_LENGTH];
        receiver.export(EXPORT_LABEL, &mut exported_secret).unwrap();

        assert_eq!(plaintext, b"hello rust");
        assert_eq!(encrypted.token.exported_secret, exported_secret);
        assert_eq!(encrypted.token.request_enc, encrypted.encapsulated_key);
    }

    #[test]
    fn empty_request_body_is_plaintext() {
        let mut csprng = StdRng::from_os_rng();
        let (_, public_key) = KemSuite::gen_keypair(&mut csprng);
        let identity = ServerIdentity {
            key_id: KEY_ID,
            public_key,
        };

        assert!(identity.encrypt_request_body(b"").unwrap().is_none());
    }
}
