"""fmt="none" attestation (WebAuthn L3 §8.7).

The authenticator declines to provide attestation data. The attStmt must be an
empty CBOR map. There is nothing to verify cryptographically; the binding to
the credential comes solely from the COSE_Key embedded in authData.

This is what Touch ID / Windows Hello / Chromium virtual authenticator return
by default when the RP requests `attestation: "none"` (which we do).
"""

from __future__ import annotations


class AttestationError(ValueError):
    pass


def verify(att_stmt: dict, auth_data, client_data_hash: bytes) -> None:
    """Validate that attStmt is the empty map. Raises on violation."""
    if att_stmt != {}:
        raise AttestationError(f"fmt=none requires empty attStmt, got {att_stmt!r}")
    # Nothing else to do. The credential public key is trusted on a Trust On
    # First Use basis; binding is established by the upcoming assertion ceremony.
