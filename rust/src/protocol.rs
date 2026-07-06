pub const ENCAPSULATED_KEY_HEADER: &str = "Ehbp-Encapsulated-Key";
pub const RESPONSE_NONCE_HEADER: &str = "Ehbp-Response-Nonce";
pub const KEYS_MEDIA_TYPE: &str = "application/ohttp-keys";
pub const KEYS_PATH: &str = "/.well-known/hpke-keys";
pub const PROBLEM_JSON_MEDIA_TYPE: &str = "application/problem+json";
pub const KEY_CONFIG_PROBLEM_TYPE: &str = "urn:ietf:params:ehbp:error:key-config";

pub const KEY_ID: u8 = 0;
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_AES_256_GCM: u16 = 0x0002;

pub const HPKE_REQUEST_INFO: &[u8] = b"ehbp request";
pub const EXPORT_LABEL: &[u8] = b"ehbp response";
pub const EXPORT_LENGTH: usize = 32;
pub const REQUEST_ENC_LENGTH: usize = 32;
pub const RESPONSE_NONCE_LENGTH: usize = 32;
pub const AES256_KEY_LENGTH: usize = 32;
pub const AES_GCM_NONCE_LENGTH: usize = 12;
pub const RESPONSE_KEY_LABEL: &[u8] = b"key";
pub const RESPONSE_NONCE_LABEL: &[u8] = b"nonce";

pub const WS_SUBPROTOCOL: &str = "ehbp.noise.v1";
pub const NOISE_PROTOCOL_NAME: &str = "Noise_NK_25519_AESGCM_SHA256";
pub const NOISE_PROLOGUE: &[u8] = b"ehbp noise websocket v1";
pub const WS_RECORD_DATA: u8 = 0x01;
pub const WS_RECORD_CLOSE: u8 = 0x02;
pub const DEFAULT_WS_MAX_MESSAGE_SIZE: usize = 1 << 20;
/// Framing added to a record payload: 1 record type byte, a 16-byte AEAD
/// tag, and margin for WebSocket read limit accounting.
pub const WS_RECORD_OVERHEAD: usize = 64;
pub const WS_HANDSHAKE_READ_LIMIT: usize = 4096;
pub const WS_REKEY_INTERVAL: u64 = 1 << 16;
/// Default cap on the WebSocket dial plus Noise handshake (SPEC Section 8.4).
pub const WS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
