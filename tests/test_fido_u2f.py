"""End-to-end test for fmt=fido-u2f.

We have to:
  1. Generate a credential P-256 keypair (lives inside the "authenticator").
  2. Generate a separate ATTESTATION P-256 keypair and wrap it in a
     self-signed X.509 cert (this stands in for the U2F batch attestation cert
     YubiKeys ship with).
  3. Build authData with the credential's COSE_Key.
  4. Build the U2F signature base: 0x00 || rpIdHash || clientDataHash || credId
     || uncompressedPub. Sign with the attestation private key.
  5. Wrap into an attestationObject with fmt="fido-u2f", attStmt={x5c, sig}.
  6. Hand it to verify_registration; expect success.

Plus a negative case where the signature is over the wrong base (the §8.6
verifier must reject).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from server import verify

from .cbor_encoder import dumps as cbor_dumps
from .test_e2e import (
    FLAG_AT,
    FLAG_UP,
    FLAG_UV,
    ORIGIN,
    RP_ID,
    _make_auth_data,
    _make_client_data,
    _make_cose_es256,
)


def _make_attestation_cert(att_priv: ec.EllipticCurvePrivateKey) -> bytes:
    """Build a tiny self-signed X.509 cert that carries att_priv's public key.

    Real YubiKey attestation certs are signed by Yubico's roots; for the local
    test we self-sign because the §8.6 verifier only consults the leaf's public
    key, not its issuer chain.
    """
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test U2F Attestation"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(att_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2026, 1, 1))
        .not_valid_after(dt.datetime(2099, 1, 1))
    )
    cert = builder.sign(att_priv, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _build_u2f_attestation_object(
    *, cred_priv, att_priv, credential_id: bytes, challenge: bytes, tamper: bool = False
):
    """Return (attestationObject, clientDataJSON)."""
    cose_key_bytes = _make_cose_es256(cred_priv.public_key())
    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=credential_id,
        cose_key=cose_key_bytes,
    )

    client_data = _make_client_data("webauthn.create", challenge)
    client_data_hash = hashlib.sha256(client_data).digest()

    # rpIdHash is the first 32 bytes of authData.
    rp_id_hash = auth_data[:32]

    # Uncompressed P-256 point form for U2F.
    cred_numbers = cred_priv.public_key().public_numbers()
    pub_uncompressed = b"\x04" + cred_numbers.x.to_bytes(32, "big") + cred_numbers.y.to_bytes(32, "big")

    signed = b"\x00" + rp_id_hash + client_data_hash + credential_id + pub_uncompressed
    if tamper:
        signed = signed[:-1] + bytes([signed[-1] ^ 0x01])
    sig = att_priv.sign(signed, ec.ECDSA(hashes.SHA256()))

    cert_der = _make_attestation_cert(att_priv)

    att_obj = cbor_dumps(
        {
            "fmt": "fido-u2f",
            "authData": auth_data,
            "attStmt": {"x5c": [cert_der], "sig": sig},
        }
    )
    return att_obj, client_data


def test_fido_u2f_happy_path():
    cred_priv = ec.generate_private_key(ec.SECP256R1())
    att_priv = ec.generate_private_key(ec.SECP256R1())
    credential_id = secrets.token_bytes(32)
    challenge = secrets.token_bytes(32)

    att_obj, client_data = _build_u2f_attestation_object(
        cred_priv=cred_priv,
        att_priv=att_priv,
        credential_id=credential_id,
        challenge=challenge,
    )

    result = verify.verify_registration(
        client_data_json=client_data,
        attestation_object=att_obj,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    assert result.credential_id == credential_id
    assert result.public_key.alg == -7


def test_fido_u2f_tampered_signature_rejected():
    cred_priv = ec.generate_private_key(ec.SECP256R1())
    att_priv = ec.generate_private_key(ec.SECP256R1())
    credential_id = secrets.token_bytes(32)
    challenge = secrets.token_bytes(32)

    att_obj, client_data = _build_u2f_attestation_object(
        cred_priv=cred_priv,
        att_priv=att_priv,
        credential_id=credential_id,
        challenge=challenge,
        tamper=True,
    )

    with pytest.raises(verify.VerificationError, match="fido-u2f"):
        verify.verify_registration(
            client_data_json=client_data,
            attestation_object=att_obj,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
