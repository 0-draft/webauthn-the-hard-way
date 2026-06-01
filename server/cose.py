"""COSE_Key parser, RFC 8152 / RFC 9052, subset for WebAuthn.

A WebAuthn credential's public key arrives inside `authenticatorData` as a
COSE_Key. COSE_Key is just a CBOR map keyed by negative or positive integers.

The keys we care about:
  1 (kty): key type. 2 = EC2, 3 = RSA.
  3 (alg): signature algorithm. -7 = ES256, -257 = RS256.

For EC2 keys (kty=2):
  -1 (crv): curve. 1 = P-256.
  -2 (x):   x coordinate, big-endian 32 bytes for P-256.
  -3 (y):   y coordinate, big-endian 32 bytes for P-256.

For RSA keys (kty=3):
  -1 (n): modulus, big-endian.
  -2 (e): public exponent, big-endian (usually 0x010001).

The output is a `cryptography` library public key object, ready for `.verify()`.
We deliberately stop at ES256 + RS256: those two cover essentially every real
authenticator (YubiKey, Touch ID, Windows Hello, Android, Chromium virtual).
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# COSE_Key labels (RFC 8152 §7).
LABEL_KTY = 1
LABEL_ALG = 3

# Key types.
KTY_EC2 = 2
KTY_RSA = 3

# Algorithms.
ALG_ES256 = -7
ALG_RS256 = -257

# EC2 curve identifiers (RFC 8152 §13.1).
CRV_P256 = 1


@dataclass
class CoseKey:
    """Decoded COSE_Key plus the cryptography public key object."""

    kty: int
    alg: int
    public_key: object  # ec.EllipticCurvePublicKey or rsa.RSAPublicKey

    def verify(self, signature: bytes, message: bytes) -> None:
        """Verify `signature` over `message`. Raises on failure.

        Per RFC 8152 §8, ES256 expects an ASN.1 DER-encoded ECDSA signature.
        WebAuthn authenticators produce exactly that format inside the
        attestation statement and the assertion signature, so we hand it to
        `cryptography` as-is.
        """
        if self.alg == ALG_ES256:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif self.alg == ALG_RS256:
            self.public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        else:
            raise ValueError(f"unsupported COSE alg: {self.alg}")


class CoseKeyError(ValueError):
    pass


def parse(cose_map: dict) -> CoseKey:
    """Turn a decoded COSE_Key dict into a CoseKey with a public key object."""
    if not isinstance(cose_map, dict):
        raise CoseKeyError(f"COSE_Key must be a CBOR map, got {type(cose_map).__name__}")

    kty = cose_map.get(LABEL_KTY)
    alg = cose_map.get(LABEL_ALG)
    if kty is None:
        raise CoseKeyError("COSE_Key missing kty (label 1)")
    if alg is None:
        raise CoseKeyError("COSE_Key missing alg (label 3)")

    if kty == KTY_EC2:
        return _parse_ec2(cose_map, alg)
    if kty == KTY_RSA:
        return _parse_rsa(cose_map, alg)
    raise CoseKeyError(f"unsupported kty: {kty}")


def _parse_ec2(m: dict, alg: int) -> CoseKey:
    if alg != ALG_ES256:
        raise CoseKeyError(f"EC2 key with unsupported alg: {alg}")
    crv = m.get(-1)
    x = m.get(-2)
    y = m.get(-3)
    if crv != CRV_P256:
        raise CoseKeyError(f"unsupported EC2 curve: {crv}")
    if not (isinstance(x, (bytes, bytearray)) and isinstance(y, (bytes, bytearray))):
        raise CoseKeyError("EC2 key missing x/y coordinates")
    if len(x) != 32 or len(y) != 32:
        # P-256 coordinates are exactly 32 bytes (big-endian, leading zeros preserved).
        raise CoseKeyError(f"P-256 coordinate length wrong: x={len(x)}, y={len(y)}")

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    return CoseKey(kty=KTY_EC2, alg=ALG_ES256, public_key=public_numbers.public_key())


def _parse_rsa(m: dict, alg: int) -> CoseKey:
    if alg != ALG_RS256:
        raise CoseKeyError(f"RSA key with unsupported alg: {alg}")
    n = m.get(-1)
    e = m.get(-2)
    if not (isinstance(n, (bytes, bytearray)) and isinstance(e, (bytes, bytearray))):
        raise CoseKeyError("RSA key missing n/e")

    public_numbers = rsa.RSAPublicNumbers(
        e=int.from_bytes(e, "big"),
        n=int.from_bytes(n, "big"),
    )
    return CoseKey(kty=KTY_RSA, alg=ALG_RS256, public_key=public_numbers.public_key())
