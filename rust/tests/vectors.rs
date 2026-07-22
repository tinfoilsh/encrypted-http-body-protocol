use serde::Deserialize;
use tinfoil_ehbp::{
    derive_response_keys, ServerIdentity, SessionRecoveryToken, AEAD_AES_256_GCM, KDF_HKDF_SHA256,
    KEM_X25519_HKDF_SHA256, KEY_ID,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveVector {
    exported_secret: String,
    request_enc: String,
    response_nonce: String,
    derived_key: String,
    derived_nonce_base: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseVector {
    exported_secret: String,
    request_enc: String,
    response_nonce: String,
    plaintext: String,
    encrypted_response: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenVector {
    exported_secret: String,
    request_enc: String,
}

#[test]
fn derives_response_keys_from_shared_vector() {
    let vector: DeriveVector =
        serde_json::from_str(include_str!("../../test-vectors/derive.json")).unwrap();

    let key_material = derive_response_keys(
        &hex::decode(vector.exported_secret).unwrap(),
        &hex::decode(vector.request_enc).unwrap(),
        &hex::decode(vector.response_nonce).unwrap(),
    )
    .unwrap();

    assert_eq!(hex::encode(key_material.key), vector.derived_key);
    assert_eq!(
        hex::encode(key_material.nonce_base),
        vector.derived_nonce_base
    );
}

#[test]
fn decrypts_response_from_shared_vector() {
    let vector: ResponseVector =
        serde_json::from_str(include_str!("../../test-vectors/response-decryption.json")).unwrap();
    let token = SessionRecoveryToken::new(
        hex::decode(vector.exported_secret).unwrap(),
        hex::decode(vector.request_enc).unwrap(),
    )
    .unwrap();

    let plaintext = token
        .decrypt_response_body(
            &hex::decode(vector.response_nonce).unwrap(),
            &hex::decode(vector.encrypted_response).unwrap(),
        )
        .unwrap();

    assert_eq!(hex::encode(plaintext), vector.plaintext);
}

#[test]
fn incrementally_decrypts_response_from_shared_vector() {
    let vector: ResponseVector =
        serde_json::from_str(include_str!("../../test-vectors/response-decryption.json")).unwrap();
    let token = SessionRecoveryToken::new(
        hex::decode(vector.exported_secret).unwrap(),
        hex::decode(vector.request_enc).unwrap(),
    )
    .unwrap();
    let encrypted = hex::decode(vector.encrypted_response).unwrap();
    let mut decryptor = token
        .response_decryptor(&hex::decode(vector.response_nonce).unwrap())
        .unwrap();

    assert!(decryptor.push(&encrypted[..3]).unwrap().is_empty());
    let plaintext = decryptor.push(&encrypted[3..]).unwrap().concat();
    decryptor.finish().unwrap();

    assert_eq!(hex::encode(plaintext), vector.plaintext);
}

#[test]
fn session_recovery_token_serializes_shared_json_shape() {
    let vector: TokenVector = serde_json::from_str(include_str!(
        "../../test-vectors/session-recovery-token.json"
    ))
    .unwrap();
    let json = serde_json::to_string(&serde_json::json!({
        "exportedSecret": vector.exported_secret,
        "requestEnc": vector.request_enc,
    }))
    .unwrap();

    let token: SessionRecoveryToken = serde_json::from_str(&json).unwrap();
    let serialized: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&token).unwrap()).unwrap();
    let expected: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(serialized, expected);
}

#[test]
fn parses_and_marshals_public_config() {
    let public_key = [7u8; 32];
    let mut config = Vec::new();
    config.push(KEY_ID);
    config.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&public_key);
    config.extend_from_slice(&(4u16).to_be_bytes());
    config.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());

    let identity = ServerIdentity::unmarshal_public_config(&config).unwrap();

    assert_eq!(identity.public_key_bytes(), public_key);
    assert_eq!(identity.marshal_public_config(), config);
}

#[test]
fn parses_first_public_config_and_ignores_additional_configs() {
    let first_public_key = [7u8; 32];
    let second_public_key = [8u8; 32];

    let mut config = Vec::new();
    config.push(KEY_ID);
    config.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&first_public_key);
    config.extend_from_slice(&(4u16).to_be_bytes());
    config.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());
    config.push(KEY_ID);
    config.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&second_public_key);
    config.extend_from_slice(&(4u16).to_be_bytes());
    config.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    config.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());

    let identity = ServerIdentity::unmarshal_public_config(&config).unwrap();

    assert_eq!(identity.public_key_bytes(), first_public_key);
}
