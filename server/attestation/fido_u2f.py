"""fmt="fido-u2f" attestation (WebAuthn L3 §8.6).

Used by CTAP1 (U2F) authenticators: YubiKey 4 / NEO, Solo v1, older Feitians.
Modern CTAP2 authenticators usually emit fmt="packed", but plenty of YubiKeys
still ship CTAP1-only.

attStmt = {
  "x5c": [attestation_cert_DER],   # single cert (no chain)
  "sig": <DER ECDSA signature>,
}

Signature base, per §8.6 verification step 4:

    0x00 || rpIdHash (32) || clientDataHash (32) || credentialId || publicKey

where `publicKey` is the credential public key serialized as a SINGLE-BYTE
prefix 0x04 followed by the 32-byte X coordinate followed by the 32-byte Y
coordinate. This is the X9.62 uncompressed point encoding.

This format is rigid: alg is implicitly ES256 (-7), curve is P-256, the cert
is leaf-only. We enforce those constraints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

if TYPE_CHECKING:
    from ..parsers import AuthenticatorData


class AttestationError(ValueError):
    pass


def verify(att_stmt: dict, auth_data: AuthenticatorData, client_data_hash: bytes) -> None:
    # Step 1: check attStmt has the required fields with the required shapes.
    x5c = att_stmt.get("x5c")
    sig = att_stmt.get("sig")
    if not (isinstance(x5c, list) and len(x5c) == 1):
        raise AttestationError("fido-u2f x5c must be a 1-element array")
    if not isinstance(sig, (bytes, bytearray)):
        raise AttestationError("fido-u2f sig must be a byte string")
    if auth_data.attested_credential_data is None:
        raise AttestationError("fido-u2f requires attested credential data in authData")

    leaf_der = x5c[0]
    if not isinstance(leaf_der, (bytes, bytearray)):
        raise AttestationError("fido-u2f x5c entry must be bytes")

    # Step 2: load the attestation certificate. Its public key signs the
    # base below.
    cert = x509.load_der_x509_certificate(bytes(leaf_der))
    cert_pub = cert.public_key()
    if not isinstance(cert_pub, ec.EllipticCurvePublicKey):
        raise AttestationError("fido-u2f attestation cert must carry an EC public key")
    if not isinstance(cert_pub.curve, ec.SECP256R1):
        raise AttestationError("fido-u2f attestation cert must use P-256")

    # Step 3: re-extract the credential public key as a U2F-style uncompressed
    # point. WebAuthn stores it inside authData as a COSE_Key; we already parsed
    # that and have x/y available. fido-u2f requires the original X9.62 form.
    cose_key = auth_data.attested_credential_data.credential_public_key
    if cose_key.alg != -7:
        raise AttestationError("fido-u2f requires ES256 credential key")
    cred_pub = cose_key.public_key
    if not isinstance(cred_pub, ec.EllipticCurvePublicKey):
        raise AttestationError("fido-u2f credential must be EC")
    cred_numbers = cred_pub.public_numbers()
    pub_uncompressed = b"\x04" + cred_numbers.x.to_bytes(32, "big") + cred_numbers.y.to_bytes(32, "big")

    credential_id = auth_data.attested_credential_data.credential_id

    # Step 4: build the signature base. §8.6 verification step 4.
    signed = b"\x00" + auth_data.rp_id_hash + client_data_hash + credential_id + pub_uncompressed

    # Step 5: verify the signature with the attestation cert's public key.
    try:
        cert_pub.verify(bytes(sig), signed, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        raise AttestationError(f"fido-u2f signature failed: {e}") from e

    # WebAuthn L3 §8.6 also flags the AT bit must be set; that is already
    # enforced by `verify_registration` requiring attested credential data.
