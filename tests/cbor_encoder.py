"""Tiny CBOR encoder for building test fixtures.

The repo's `server/cbor.py` only decodes. To exercise the verifier end-to-end we
need to BUILD an attestationObject, which means encoding CBOR for:

  - the attestationObject (a 3-key map)
  - the credentialPublicKey (a COSE_Key map embedded inside authData)

This encoder supports the same major types as the decoder: uint, nint, byte
string, text string, array, map. Definite-length only (authenticators use
definite-length in practice, and the decoder accepts both, so test fixtures
should pick the simpler encoding).

Map key ordering matches insertion order. For COSE_Key specifically we follow
CTAP2's canonical ordering (length-then-byte order of the encoded key) only
where the verifier or a real authenticator depends on it; for the tests in
this repo, insertion order is enough.
"""

from __future__ import annotations

import struct
from typing import Any


def _encode_argument(major: int, value: int) -> bytes:
    """Encode the initial byte plus the integer "argument" per RFC 8949 §3."""
    if value < 0:
        raise ValueError("argument must be non-negative; encode negatives via major type 1")
    head = major << 5
    if value < 24:
        return bytes([head | value])
    if value < 0x100:
        return bytes([head | 24, value])
    if value < 0x10000:
        return bytes([head | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([head | 26]) + struct.pack(">I", value)
    if value < 0x10000000000000000:
        return bytes([head | 27]) + struct.pack(">Q", value)
    raise ValueError("argument too large for definite-length encoding")


def dumps(value: Any) -> bytes:
    if isinstance(value, bool):
        return bytes([0xF5]) if value else bytes([0xF4])
    if value is None:
        return bytes([0xF6])
    if isinstance(value, int):
        if value >= 0:
            return _encode_argument(0, value)
        return _encode_argument(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        return _encode_argument(2, len(b)) + b
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _encode_argument(3, len(b)) + b
    if isinstance(value, list):
        out = _encode_argument(4, len(value))
        for item in value:
            out += dumps(item)
        return out
    if isinstance(value, dict):
        out = _encode_argument(5, len(value))
        for k, v in value.items():
            out += dumps(k)
            out += dumps(v)
        return out
    raise TypeError(f"unsupported value type for CBOR encoder: {type(value).__name__}")
