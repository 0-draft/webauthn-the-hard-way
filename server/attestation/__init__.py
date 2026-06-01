"""Attestation format dispatch.

Each format ("none", "packed", "fido-u2f", "tpm", "android-key", "apple", ...)
gets its own verifier module. We implement three of them:
  - "none":     authenticator declines to attest. attStmt is empty.
  - "packed":   modern CTAP2 default. Self attestation or full (x5c).
  - "fido-u2f": legacy CTAP1 / U2F authenticators (YubiKey 4 / NEO etc.).
                Same idea, different signature base.

Adding a new format = drop a new module and register it in the FORMATS table.
"""

from . import fido_u2f, none, packed

FORMATS = {
    "none": none.verify,
    "packed": packed.verify,
    "fido-u2f": fido_u2f.verify,
}


def get(fmt: str):
    if fmt not in FORMATS:
        raise ValueError(f"unsupported attestation format: {fmt!r}")
    return FORMATS[fmt]
