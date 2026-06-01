"""WebAuthn registration and authentication verification.

This file walks the two main ceremonies in WebAuthn L3:

  - §7.1: Registering a New Credential (verifyRegistrationResponse).
  - §7.2: Verifying an Authentication Assertion (verifyAuthenticationResponse).

Each step is annotated with the spec step number so you can compare side-by-side.

The shape of the input matches what the browser sends back through our own
small JSON envelope on top of the WebAuthn `PublicKeyCredential`. The Flask
layer takes care of parsing the JSON; this module operates on bytes that have
already been base64url-decoded.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from . import attestation, cose, parsers


class VerificationError(ValueError):
    pass


@dataclass
class RegistrationResult:
    credential_id: bytes
    public_key: cose.CoseKey
    public_key_cbor: bytes      # raw COSE_Key bytes, what we will need at assertion time
    sign_count: int
    aaguid: bytes
    backup_eligible: bool
    backup_state: bool


@dataclass
class StoredCredential:
    credential_id: bytes
    public_key_cbor: bytes
    sign_count: int
    aaguid: bytes
    user_handle: bytes          # opaque user id we picked at registration time


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _parse_client_data(client_data_json: bytes, expected_type: str, expected_challenge: bytes,
                       expected_origin: str) -> None:
    """Common clientDataJSON checks shared by both ceremonies (§7.1 steps 7-10, §7.2 steps 11-14)."""
    try:
        cdj = json.loads(client_data_json)
    except json.JSONDecodeError as e:
        raise VerificationError(f"clientDataJSON is not valid JSON: {e}") from e

    if cdj.get("type") != expected_type:
        raise VerificationError(f"clientDataJSON.type mismatch: expected {expected_type!r}, got {cdj.get('type')!r}")

    # The challenge in clientDataJSON is base64url WITHOUT padding (per the
    # CollectedClientData IDL).  We compare on raw bytes to avoid being tricked
    # by base64 normalization differences.
    received_b64 = cdj.get("challenge", "")
    received = _b64url_decode(received_b64)
    if received != expected_challenge:
        raise VerificationError("clientDataJSON.challenge mismatch")

    if cdj.get("origin") != expected_origin:
        raise VerificationError(
            f"clientDataJSON.origin mismatch: expected {expected_origin!r}, got {cdj.get('origin')!r}"
        )

    # `crossOrigin` and `tokenBinding` are present in the spec but optional in
    # practice; we tolerate either.


def _b64url_decode(s: str) -> bytes:
    """base64url decode tolerating missing padding."""
    if not isinstance(s, str):
        raise VerificationError("base64url value is not a string")
    pad = "=" * (-len(s) % 4)
    import base64
    return base64.urlsafe_b64decode(s + pad)


def verify_registration(
    *,
    client_data_json: bytes,
    attestation_object: bytes,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verification: bool = True,
) -> RegistrationResult:
    """WebAuthn L3 §7.1 Registering a New Credential.

    Steps 1-6 are concerned with how the browser produced the response. They are
    enforced by the user agent itself, so we start at step 7 (we receive `response`
    already split into its three byte strings).
    """
    # Step 7: parse clientDataJSON (already in bytes; we parse JSON inside).
    # Step 8: verify type == "webauthn.create".
    # Step 9: verify challenge.
    # Step 10: verify origin.
    _parse_client_data(client_data_json, "webauthn.create", expected_challenge, expected_origin)

    # Step 11: compute hash of clientDataJSON.
    client_data_hash = _sha256(client_data_json)

    # Step 12: parse attestationObject -> {fmt, authData, attStmt}.
    att = parsers.parse_attestation_object(attestation_object)

    # Step 13: verify rpIdHash matches SHA-256(rpId).
    expected_rp_id_hash = _sha256(expected_rp_id.encode("utf-8"))
    if att.auth_data.rp_id_hash != expected_rp_id_hash:
        raise VerificationError("authData.rpIdHash does not match SHA-256(rpId)")

    # Step 14: verify the UP (user present) flag is set.
    if not att.auth_data.user_present:
        raise VerificationError("authData.flags.UP (user present) is not set")

    # Step 15: if user verification required, verify UV flag.
    if require_user_verification and not att.auth_data.user_verified:
        raise VerificationError("authData.flags.UV (user verified) is not set")

    # Step 16: verify the algorithm is one we asked for (we asked for ES256 / RS256).
    if att.auth_data.attested_credential_data is None:
        raise VerificationError("authData.flags.AT (attested credential data) is not set")
    cose_alg = att.auth_data.attested_credential_data.credential_public_key.alg
    if cose_alg not in (cose.ALG_ES256, cose.ALG_RS256):
        raise VerificationError(f"unsupported COSE alg in credential: {cose_alg}")

    # Steps 17-18: verify the attestation statement. Format-specific verifier.
    verifier = attestation.get(att.fmt)
    verifier(att.att_stmt, att.auth_data, client_data_hash)

    # Step 19: check the credentialId is not already registered to another user.
    # We do that check at the storage layer (app.py) because it requires the DB.

    cred = att.auth_data.attested_credential_data
    return RegistrationResult(
        credential_id=cred.credential_id,
        public_key=cred.credential_public_key,
        public_key_cbor=cred.credential_public_key_cbor,
        sign_count=att.auth_data.sign_count,
        aaguid=cred.aaguid,
        backup_eligible=att.auth_data.backup_eligible,
        backup_state=att.auth_data.backup_state,
    )


@dataclass
class AssertionResult:
    new_sign_count: int
    user_verified: bool
    backup_state: bool


def verify_assertion(
    *,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    stored: StoredCredential,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verification: bool = True,
) -> AssertionResult:
    """WebAuthn L3 §7.2 Verifying an Authentication Assertion."""
    # Steps 1-10 are about looking up the credential in our store; that has
    # already been done by the caller (it located `stored` via credentialId).

    # Step 11: parse clientDataJSON. Type must be "webauthn.get".
    # Step 12-14: verify type / challenge / origin (folded into one helper).
    _parse_client_data(client_data_json, "webauthn.get", expected_challenge, expected_origin)

    # Step 15: parse authenticatorData (no attested credential data this time;
    # it's only present at registration).
    ad = parsers.parse_authenticator_data(authenticator_data)

    # Step 16: rpIdHash check.
    expected_rp_id_hash = _sha256(expected_rp_id.encode("utf-8"))
    if ad.rp_id_hash != expected_rp_id_hash:
        raise VerificationError("authData.rpIdHash mismatch on assertion")

    # Step 17: UP check.
    if not ad.user_present:
        raise VerificationError("authData.flags.UP not set on assertion")

    # Step 18: UV check.
    if require_user_verification and not ad.user_verified:
        raise VerificationError("authData.flags.UV not set on assertion")

    # Step 19: compute client data hash.
    client_data_hash = _sha256(client_data_json)

    # Step 20: signature verification.
    #
    # The signature is over authenticatorData || SHA-256(clientDataJSON).
    # Re-hydrate the stored COSE_Key into a CoseKey first.  We do this on each
    # request rather than storing the cryptography object so the store remains
    # serializable.
    from . import cbor  # local import to avoid circular at module top
    cose_map = cbor.loads(stored.public_key_cbor)
    cose_key = cose.parse(cose_map)

    signed = ad.raw + client_data_hash
    try:
        cose_key.verify(signature, signed)
    except Exception as e:
        raise VerificationError(f"assertion signature failed: {e}") from e

    # Step 21: signCount must increase, OR both stored and received are 0 (the
    # spec allows authenticators that do not implement a counter; both ends
    # stay at 0 forever).
    if ad.sign_count == 0 and stored.sign_count == 0:
        # No-op authenticator; both ends still zero, nothing to compare.
        new_sign_count = 0
    elif ad.sign_count <= stored.sign_count:
        # Could indicate a cloned authenticator. Spec permits the RP to refuse
        # or to log and proceed; we refuse.
        raise VerificationError(
            f"signCount did not increase (stored={stored.sign_count}, received={ad.sign_count})"
        )
    else:
        new_sign_count = ad.sign_count

    return AssertionResult(
        new_sign_count=new_sign_count,
        user_verified=ad.user_verified,
        backup_state=ad.backup_state,
    )
