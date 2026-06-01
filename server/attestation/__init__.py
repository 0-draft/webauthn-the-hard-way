"""Attestation format dispatch.

Each format ("none", "packed", "fido-u2f", "tpm", "android-key", "apple", ...)
gets its own verifier module. We implement two of them:
  - "none":   the authenticator declines to attest. The attStmt is an empty map.
  - "packed": the most common real-world format. Two sub-variants (self / x5c).

Adding a new format = drop a new module and register it in the FORMATS table.
"""

from . import none, packed

FORMATS = {
    "none": none.verify,
    "packed": packed.verify,
}


def get(fmt: str):
    if fmt not in FORMATS:
        raise ValueError(f"unsupported attestation format: {fmt!r}")
    return FORMATS[fmt]
