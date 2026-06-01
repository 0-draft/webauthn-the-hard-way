"""fmt="packed" attestation (WebAuthn L3 §8.2).

The packed format is FIDO's "compact" attestation. Two variants:

  1. **x5c (full attestation)**: attStmt has {alg, sig, x5c}. The signature is
     computed by an attestation private key; its certificate chain is in x5c.
     The leaf cert's public key verifies sig over `authData || clientDataHash`.

  2. **Self attestation**: attStmt has {alg, sig} (no x5c). The signature is
     computed by the credential's own private key. We verify sig with the
     credentialPublicKey already parsed out of authData. alg must match the
     COSE_Key's alg.

Production verifiers also check that the leaf cert chains to a known root
(usually via FIDO MDS). For "the hard way" we stop at signature verification
and parse the chain only enough to surface the leaf's subject; trust anchoring
is out of scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes

if TYPE_CHECKING:
    from ..parsers import AuthenticatorData


# COSE algorithm identifiers we accept inside attStmt.alg.
ALG_ES256 = -7
ALG_RS256 = -257


class AttestationError(ValueError):
    pass


def verify(att_stmt: dict, auth_data: "AuthenticatorData", client_data_hash: bytes) -> None:
    alg = att_stmt.get("alg")
    sig = att_stmt.get("sig")
    x5c = att_stmt.get("x5c")

    if alg is None or not isinstance(alg, int):
        raise AttestationError("packed attStmt missing integer alg")
    if not isinstance(sig, (bytes, bytearray)):
        raise AttestationError("packed attStmt missing byte-string sig")
    sig = bytes(sig)

    # The signature is always computed over the concatenation. WebAuthn L3 §8.2
    # step 2: "Concatenate authenticatorData and clientDataHash to form the
    # signed-over data."  Note that we use the raw authData bytes, not the
    # parsed dataclass; the authenticator signs the exact bytes.
    signed = auth_data.raw + client_data_hash

    if x5c:
        if not isinstance(x5c, list) or not x5c:
            raise AttestationError("packed attStmt x5c must be a non-empty array")
        _verify_with_x5c(alg, sig, signed, x5c, auth_data)
    else:
        _verify_self(alg, sig, signed, auth_data)


def _verify_self(alg: int, sig: bytes, signed: bytes, auth_data: "AuthenticatorData") -> None:
    if auth_data.attested_credential_data is None:
        raise AttestationError("self attestation requires attested credential data")
    cose_key = auth_data.attested_credential_data.credential_public_key

    if alg != cose_key.alg:
        # Self attestation: the credential signs itself, so the attestation alg
        # must equal the credential's alg.
        raise AttestationError(
            f"self attestation alg mismatch: attStmt.alg={alg}, COSE_Key.alg={cose_key.alg}"
        )

    try:
        cose_key.verify(sig, signed)
    except Exception as e:
        raise AttestationError(f"self attestation signature failed: {e}") from e


def _verify_with_x5c(alg: int, sig: bytes, signed: bytes, x5c: list, auth_data: "AuthenticatorData") -> None:
    # x5c is a list of DER-encoded X.509 certificates. The leaf is x5c[0].
    leaf_der = x5c[0]
    if not isinstance(leaf_der, (bytes, bytearray)):
        raise AttestationError("packed x5c entries must be byte strings")
    leaf = x509.load_der_x509_certificate(bytes(leaf_der))
    public_key = leaf.public_key()

    if alg == ALG_ES256:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise AttestationError("alg=ES256 but x5c leaf is not an EC key")
        try:
            public_key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise AttestationError(f"x5c ES256 signature failed: {e}") from e
    elif alg == ALG_RS256:
        try:
            public_key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise AttestationError(f"x5c RS256 signature failed: {e}") from e
    else:
        raise AttestationError(f"unsupported attestation alg with x5c: {alg}")

    # WebAuthn L3 §8.2 step 2.2 also requires verifying that the AAGUID inside
    # an attached extension matches the one in authData. We stop short of that
    # to keep the lesson focused on the signature step. A production verifier
    # would inspect the `id-fido-gen-ce-aaguid` extension (OID 1.3.6.1.4.1.45724.1.1.4).
