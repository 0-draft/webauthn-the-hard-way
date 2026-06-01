"""End-to-end ceremony tests, server-side.

We build the attestationObject + clientDataJSON the way a real authenticator
would, hand it to verify_registration, then build an assertion signature and
hand that to verify_assertion. No browser, no Touch ID; this exercises every
byte of the verification pipeline.

Three flows:
  1. fmt=none, ES256 key, registration -> assertion -> assertion replay rejected.
  2. fmt=packed self attestation, ES256, registration succeeds.
  3. fmt=packed self attestation with mismatched alg, registration rejected.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from server import verify

from .cbor_encoder import dumps as cbor_dumps

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_client_data(ceremony: str, challenge: bytes) -> bytes:
    """Synthesize clientDataJSON matching what a real browser would send."""
    return json.dumps(
        {
            "type": ceremony,
            "challenge": _b64url(challenge),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _make_cose_es256(pub) -> bytes:
    """Encode a P-256 cryptography public key as COSE_Key bytes."""
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return cbor_dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})


def _make_auth_data(
    *,
    flags: int,
    sign_count: int,
    aaguid: bytes = b"\x00" * 16,
    credential_id: bytes = b"",
    cose_key: bytes = b"",
) -> bytes:
    """Assemble the authenticatorData byte layout."""
    out = bytearray()
    out += RP_ID_HASH
    out.append(flags)
    out += struct.pack(">I", sign_count)
    if flags & FLAG_AT:
        out += aaguid
        out += struct.pack(">H", len(credential_id))
        out += credential_id
        out += cose_key
    return bytes(out)


# ---------- fmt=none ----------


def test_e2e_none_registration_then_assertion():
    # 1. authenticator generates a P-256 keypair.
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    cose_key_bytes = _make_cose_es256(pub)

    credential_id = secrets.token_bytes(32)
    aaguid = bytes.fromhex("00" * 16)
    registration_sign_count = 0

    # 2. registration: build authData with attested credential data + AT/UV/UP flags.
    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=registration_sign_count,
        aaguid=aaguid,
        credential_id=credential_id,
        cose_key=cose_key_bytes,
    )

    att_obj = cbor_dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
    challenge = secrets.token_bytes(32)
    client_data = _make_client_data("webauthn.create", challenge)

    result = verify.verify_registration(
        client_data_json=client_data,
        attestation_object=att_obj,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_user_verification=True,
    )

    assert result.credential_id == credential_id
    assert result.public_key.alg == -7
    assert result.sign_count == registration_sign_count

    # Build the StoredCredential as the RP would.
    stored = verify.StoredCredential(
        credential_id=result.credential_id,
        public_key_cbor=result.public_key_cbor,
        sign_count=result.sign_count,
        aaguid=result.aaguid,
        user_handle=b"user-1",
    )

    # 3. assertion ceremony.
    assertion_challenge = secrets.token_bytes(32)
    assertion_auth_data = _make_auth_data(
        flags=FLAG_UV | FLAG_UP,
        sign_count=registration_sign_count + 1,
    )
    assertion_client_data = _make_client_data("webauthn.get", assertion_challenge)
    client_data_hash = hashlib.sha256(assertion_client_data).digest()
    signed = assertion_auth_data + client_data_hash
    signature = priv.sign(signed, ec.ECDSA(hashes.SHA256()))

    result2 = verify.verify_assertion(
        client_data_json=assertion_client_data,
        authenticator_data=assertion_auth_data,
        signature=signature,
        stored=stored,
        expected_challenge=assertion_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    assert result2.new_sign_count == 1
    assert result2.user_verified is True

    # 4. replay: same signature against same stored.sign_count must now fail
    #    because sign_count did not increase.
    stored.sign_count = result2.new_sign_count
    with pytest.raises(verify.VerificationError):
        verify.verify_assertion(
            client_data_json=assertion_client_data,
            authenticator_data=assertion_auth_data,
            signature=signature,
            stored=stored,
            expected_challenge=assertion_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )


def test_e2e_origin_mismatch_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    cose_key_bytes = _make_cose_es256(pub)
    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=b"\x01" * 16,
        cose_key=cose_key_bytes,
    )
    att_obj = cbor_dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
    challenge = secrets.token_bytes(32)
    # clientDataJSON claims an attacker origin.
    bad_client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": _b64url(challenge),
            "origin": "https://evil.example",
        },
        separators=(",", ":"),
    ).encode()

    with pytest.raises(verify.VerificationError, match="origin mismatch"):
        verify.verify_registration(
            client_data_json=bad_client_data,
            attestation_object=att_obj,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )


def test_e2e_challenge_mismatch_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    cose_key_bytes = _make_cose_es256(priv.public_key())
    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=b"\x02" * 16,
        cose_key=cose_key_bytes,
    )
    att_obj = cbor_dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
    sent_challenge = secrets.token_bytes(32)
    expected_challenge = secrets.token_bytes(32)
    client_data = _make_client_data("webauthn.create", sent_challenge)

    with pytest.raises(verify.VerificationError, match="challenge"):
        verify.verify_registration(
            client_data_json=client_data,
            attestation_object=att_obj,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )


# ---------- fmt=packed self attestation ----------


def test_e2e_packed_self_attestation():
    priv = ec.generate_private_key(ec.SECP256R1())
    cose_key_bytes = _make_cose_es256(priv.public_key())
    credential_id = secrets.token_bytes(32)

    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=credential_id,
        cose_key=cose_key_bytes,
    )

    challenge = secrets.token_bytes(32)
    client_data = _make_client_data("webauthn.create", challenge)
    client_data_hash = hashlib.sha256(client_data).digest()

    # Self attestation: the credential's own private key signs authData || clientDataHash.
    signature = priv.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
    att_obj = cbor_dumps(
        {
            "fmt": "packed",
            "authData": auth_data,
            "attStmt": {"alg": -7, "sig": signature},
        }
    )

    result = verify.verify_registration(
        client_data_json=client_data,
        attestation_object=att_obj,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    assert result.credential_id == credential_id


def test_e2e_packed_self_attestation_alg_mismatch_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    cose_key_bytes = _make_cose_es256(priv.public_key())  # alg=-7 inside COSE

    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=b"\x03" * 16,
        cose_key=cose_key_bytes,
    )
    challenge = secrets.token_bytes(32)
    client_data = _make_client_data("webauthn.create", challenge)
    client_data_hash = hashlib.sha256(client_data).digest()
    signature = priv.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

    # attStmt claims alg=-257 (RS256), but credential is ES256. Spec §8.2 rejects.
    att_obj = cbor_dumps(
        {
            "fmt": "packed",
            "authData": auth_data,
            "attStmt": {"alg": -257, "sig": signature},
        }
    )

    with pytest.raises(verify.VerificationError, match="alg mismatch"):
        # alg mismatch lives inside the AttestationError message;
        # verify_registration wraps it in VerificationError.
        verify.verify_registration(
            client_data_json=client_data,
            attestation_object=att_obj,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )


def test_e2e_tampered_signature_rejected():
    """If the assertion signature is flipped, verification must fail."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    cose_key_bytes = _make_cose_es256(pub)
    credential_id = secrets.token_bytes(32)
    auth_data = _make_auth_data(
        flags=FLAG_AT | FLAG_UV | FLAG_UP,
        sign_count=0,
        credential_id=credential_id,
        cose_key=cose_key_bytes,
    )
    att_obj = cbor_dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
    challenge = secrets.token_bytes(32)
    client_data = _make_client_data("webauthn.create", challenge)
    result = verify.verify_registration(
        client_data_json=client_data,
        attestation_object=att_obj,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    stored = verify.StoredCredential(
        credential_id=result.credential_id,
        public_key_cbor=result.public_key_cbor,
        sign_count=0,
        aaguid=result.aaguid,
        user_handle=b"u",
    )

    assertion_challenge = secrets.token_bytes(32)
    assertion_auth_data = _make_auth_data(flags=FLAG_UV | FLAG_UP, sign_count=1)
    assertion_client_data = _make_client_data("webauthn.get", assertion_challenge)
    client_data_hash = hashlib.sha256(assertion_client_data).digest()
    sig = bytearray(priv.sign(assertion_auth_data + client_data_hash, ec.ECDSA(hashes.SHA256())))
    sig[-1] ^= 0x01  # flip a bit

    with pytest.raises(verify.VerificationError, match="signature failed"):
        verify.verify_assertion(
            client_data_json=assertion_client_data,
            authenticator_data=assertion_auth_data,
            signature=bytes(sig),
            stored=stored,
            expected_challenge=assertion_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
