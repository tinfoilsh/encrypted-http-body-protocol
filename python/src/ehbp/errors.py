"""Exception hierarchy for the EHBP client.

Mirrors the error variants used by the reference implementations so callers can
distinguish recoverable conditions (notably key-configuration mismatch) from
hard failures.
"""


class EHBPError(Exception):
    """Base class for all EHBP errors."""


class InvalidConfigError(EHBPError):
    """The server key configuration could not be parsed or is unsupported."""


class InvalidInputError(EHBPError):
    """Caller-supplied input is invalid (bad URL, reserved header, ...)."""


class ProtocolError(EHBPError):
    """The peer violated the EHBP framing or header contract."""


class KeyConfigMismatchError(EHBPError):
    """The server reported a key-configuration mismatch (HTTP 422).

    The request was rejected before application processing completed, so it is
    safe to refresh the server key configuration and retry (SPEC Section 5.4.3).
    """


class HPKEError(EHBPError):
    """An HPKE setup, seal, or export operation failed."""


class CryptoError(EHBPError):
    """An AEAD or key-derivation operation failed."""
