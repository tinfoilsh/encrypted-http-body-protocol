"""Protocol constants for the encrypted HTTP body protocol (EHBP).

These values are shared with the Go, JS, Rust, and Swift implementations and
MUST NOT diverge; they define the on-the-wire format and the HPKE/HKDF labels.
"""

ENCAPSULATED_KEY_HEADER = "Ehbp-Encapsulated-Key"
RESPONSE_NONCE_HEADER = "Ehbp-Response-Nonce"
KEYS_MEDIA_TYPE = "application/ohttp-keys"
KEYS_PATH = "/.well-known/hpke-keys"
PROBLEM_JSON_MEDIA_TYPE = "application/problem+json"
KEY_CONFIG_PROBLEM_TYPE = "urn:ietf:params:ehbp:error:key-config"

KEY_ID = 0
KEM_X25519_HKDF_SHA256 = 0x0020
KDF_HKDF_SHA256 = 0x0001
AEAD_AES_256_GCM = 0x0002

HPKE_REQUEST_INFO = b"ehbp request"
EXPORT_LABEL = b"ehbp response"

EXPORT_LENGTH = 32
REQUEST_ENC_LENGTH = 32
RESPONSE_NONCE_LENGTH = 32
AES256_KEY_LENGTH = 32
AES_GCM_NONCE_LENGTH = 12

RESPONSE_KEY_LABEL = b"key"
RESPONSE_NONCE_LABEL = b"nonce"

LENGTH_PREFIX_SIZE = 4
MAX_CHUNK_LENGTH = 0xFFFFFFFF
MAX_SEQUENCE = (1 << 64) - 1

WS_SUBPROTOCOL = "ehbp.noise.v1"
NOISE_PROTOCOL_NAME = "Noise_NK_25519_AESGCM_SHA256"
NOISE_PROLOGUE = b"ehbp noise websocket v1"
WS_RECORD_DATA = 0x01
WS_RECORD_CLOSE = 0x02
DEFAULT_WS_MAX_MESSAGE_SIZE = 1 << 20
# Framing added to a record payload: 1 record type byte, a 16-byte AEAD tag,
# and margin for WebSocket read limit accounting.
WS_RECORD_OVERHEAD = 64
WS_HANDSHAKE_READ_LIMIT = 4096
WS_REKEY_INTERVAL = 1 << 16
# Default cap, in seconds, on the WebSocket dial plus Noise handshake
# (SPEC Section 8.4).
WS_HANDSHAKE_TIMEOUT = 10.0
