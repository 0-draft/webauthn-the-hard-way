"""CBOR decoder, RFC 8949, subset sufficient for WebAuthn.

WebAuthn uses CBOR in two places:
  - attestationObject: a 3-key map {"fmt": text, "authData": bytes, "attStmt": map}
  - credentialPublicKey inside authData: a COSE_Key (a CBOR map with integer keys)

That means we only need:
  - major type 0: unsigned integer
  - major type 1: negative integer
  - major type 2: byte string
  - major type 3: text string
  - major type 4: array
  - major type 5: map
  - major type 7: simple values (false=20, true=21, null=22)
                  and floats are unused by WebAuthn; we ignore them.

Indefinite-length encoding (the 0x1f / 0xff dance) is rare in WebAuthn payloads
issued by real authenticators, but we still support it because some TPMs emit it.

The decoder returns a tuple (value, bytes_consumed). The wrapper `loads(buf)`
asserts the whole buffer was consumed; `loads_with_rest(buf)` returns the rest,
which matters for attestationObject parsing where authData (a byte string inside
the map) is itself parsed later as a separate byte layout.
"""

from __future__ import annotations

import struct
from typing import Any, Tuple

# CBOR major types live in the top 3 bits of the initial byte.
# RFC 8949 §3 calls these "major type 0" through "major type 7".
MT_UINT = 0
MT_NINT = 1
MT_BSTR = 2
MT_TSTR = 3
MT_ARRAY = 4
MT_MAP = 5
MT_TAG = 6
MT_SIMPLE = 7

# Sentinel for indefinite-length break (0xff in major type 7).
class _Break:
    pass


_BREAK = _Break()


class CBORDecodeError(ValueError):
    pass


def _read_argument(buf: bytes, offset: int, ai: int) -> Tuple[int, int]:
    """Read the integer "argument" that follows the initial byte.

    `ai` is the additional info (low 5 bits of the initial byte). Per RFC 8949 §3:
      0-23  : the value IS ai
      24    : next 1 byte is the value
      25    : next 2 bytes (big-endian) are the value
      26    : next 4 bytes
      27    : next 8 bytes
      28-30 : reserved, error
      31    : indefinite length (caller decides if legal here)

    Returns (value, new_offset).
    """
    if ai < 24:
        return ai, offset
    if ai == 24:
        if offset + 1 > len(buf):
            raise CBORDecodeError("truncated 1-byte argument")
        return buf[offset], offset + 1
    if ai == 25:
        if offset + 2 > len(buf):
            raise CBORDecodeError("truncated 2-byte argument")
        return struct.unpack_from(">H", buf, offset)[0], offset + 2
    if ai == 26:
        if offset + 4 > len(buf):
            raise CBORDecodeError("truncated 4-byte argument")
        return struct.unpack_from(">I", buf, offset)[0], offset + 4
    if ai == 27:
        if offset + 8 > len(buf):
            raise CBORDecodeError("truncated 8-byte argument")
        return struct.unpack_from(">Q", buf, offset)[0], offset + 8
    if ai == 31:
        # Caller must recognize this as "indefinite length". We return a sentinel.
        return -1, offset
    raise CBORDecodeError(f"reserved additional info: {ai}")


def _decode(buf: bytes, offset: int) -> Tuple[Any, int]:
    if offset >= len(buf):
        raise CBORDecodeError("unexpected end of buffer")

    initial = buf[offset]
    offset += 1
    mt = initial >> 5
    ai = initial & 0x1F

    # 0xff is the break stop code (major type 7, ai 31). We surface it as a
    # sentinel so the indefinite-length collectors can detect it.
    if initial == 0xFF:
        return _BREAK, offset

    arg, offset = _read_argument(buf, offset, ai)

    if mt == MT_UINT:
        return arg, offset

    if mt == MT_NINT:
        # RFC 8949 §3.1: encoded value n means actual value -1 - n.
        return -1 - arg, offset

    if mt == MT_BSTR:
        if arg == -1:
            return _decode_indef_string(buf, offset, is_text=False)
        end = offset + arg
        if end > len(buf):
            raise CBORDecodeError(f"byte string truncated: need {arg}, have {len(buf) - offset}")
        return bytes(buf[offset:end]), end

    if mt == MT_TSTR:
        if arg == -1:
            return _decode_indef_string(buf, offset, is_text=True)
        end = offset + arg
        if end > len(buf):
            raise CBORDecodeError(f"text string truncated: need {arg}, have {len(buf) - offset}")
        return buf[offset:end].decode("utf-8"), end

    if mt == MT_ARRAY:
        if arg == -1:
            return _decode_indef_array(buf, offset)
        items = []
        for _ in range(arg):
            item, offset = _decode(buf, offset)
            if item is _BREAK:
                raise CBORDecodeError("unexpected break inside definite-length array")
            items.append(item)
        return items, offset

    if mt == MT_MAP:
        if arg == -1:
            return _decode_indef_map(buf, offset)
        result = {}
        for _ in range(arg):
            key, offset = _decode(buf, offset)
            if key is _BREAK:
                raise CBORDecodeError("unexpected break inside definite-length map")
            value, offset = _decode(buf, offset)
            if value is _BREAK:
                raise CBORDecodeError("unexpected break inside definite-length map")
            result[key] = value
        return result, offset

    if mt == MT_TAG:
        # Tags wrap a single data item. We surface the tagged value transparently;
        # this is enough for WebAuthn (which currently uses no tags inside
        # attestationObject or COSE_Key).
        value, offset = _decode(buf, offset)
        return value, offset

    if mt == MT_SIMPLE:
        # Simple values: false=20, true=21, null=22, undefined=23. Floats live
        # at ai=25/26/27 but WebAuthn does not use them, so we leave that out.
        if arg == 20:
            return False, offset
        if arg == 21:
            return True, offset
        if arg == 22:
            return None, offset
        if arg == 23:
            return None, offset  # "undefined"; collapse to None
        raise CBORDecodeError(f"unsupported simple/float value: ai={ai} arg={arg}")

    raise CBORDecodeError(f"unknown major type {mt}")


def _decode_indef_string(buf: bytes, offset: int, is_text: bool) -> Tuple[Any, int]:
    chunks: list[bytes] = []
    while True:
        chunk, offset = _decode(buf, offset)
        if chunk is _BREAK:
            break
        if is_text and not isinstance(chunk, str):
            raise CBORDecodeError("indefinite text string contained non-text chunk")
        if not is_text and not isinstance(chunk, (bytes, bytearray)):
            raise CBORDecodeError("indefinite byte string contained non-bytes chunk")
        chunks.append(chunk.encode("utf-8") if is_text else bytes(chunk))
    joined = b"".join(chunks)
    return (joined.decode("utf-8") if is_text else joined), offset


def _decode_indef_array(buf: bytes, offset: int) -> Tuple[list, int]:
    items: list = []
    while True:
        item, offset = _decode(buf, offset)
        if item is _BREAK:
            break
        items.append(item)
    return items, offset


def _decode_indef_map(buf: bytes, offset: int) -> Tuple[dict, int]:
    result: dict = {}
    while True:
        key, offset = _decode(buf, offset)
        if key is _BREAK:
            break
        value, offset = _decode(buf, offset)
        if value is _BREAK:
            raise CBORDecodeError("indefinite map ended between key and value")
        result[key] = value
    return result, offset


def loads(buf: bytes) -> Any:
    """Decode a CBOR item and assert the buffer is fully consumed."""
    value, consumed = _decode(buf, 0)
    if consumed != len(buf):
        raise CBORDecodeError(
            f"trailing bytes: consumed {consumed} of {len(buf)} "
            f"(use loads_with_rest if the trailing data is expected)"
        )
    return value


def loads_with_rest(buf: bytes) -> Tuple[Any, bytes]:
    """Decode one CBOR item and return (value, remaining_bytes).

    Used by the COSE_Key parser inside authenticatorData, where the COSE_Key is
    one CBOR item followed by attestation-format-specific extensions.
    """
    value, consumed = _decode(buf, 0)
    return value, bytes(buf[consumed:])
