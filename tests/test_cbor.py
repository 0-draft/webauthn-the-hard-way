"""Tests for the CBOR decoder, drawn from RFC 8949 Appendix A.

Each (hex, decoded) pair below is taken verbatim from the spec's "Examples of
Encoded CBOR Data Items" table. The IETF intends this list as a conformance
suite; if our decoder matches, the wire format is right.

We deliberately skip:
  - floats (RFC 8949 unused by WebAuthn)
  - "tag" tests where the tag carries semantics we have not implemented
"""

from __future__ import annotations

import pytest

from server import cbor


# (hex_input, expected_python_value)
# Curated subset of RFC 8949 Appendix A relevant to integers, strings, arrays, maps.
VECTORS = [
    ("00", 0),
    ("01", 1),
    ("0a", 10),
    ("17", 23),
    ("1818", 24),
    ("1819", 25),
    ("1864", 100),
    ("1903e8", 1000),
    ("1a000f4240", 1_000_000),
    ("1b000000e8d4a51000", 1_000_000_000_000),
    ("20", -1),
    ("29", -10),
    ("3863", -100),
    ("3903e7", -1000),
    ("40", b""),
    ("4401020304", b"\x01\x02\x03\x04"),
    ("60", ""),
    ("6161", "a"),
    ("6449455446", "IETF"),
    ("62225c", '"\\'),
    ("80", []),
    ("83010203", [1, 2, 3]),
    ("8301820203820405", [1, [2, 3], [4, 5]]),
    ("a0", {}),
    ("a201020304", {1: 2, 3: 4}),
    ("a26161016162820203", {"a": 1, "b": [2, 3]}),
    ("826161a161626163", ["a", {"b": "c"}]),
    ("a56161614161626142616361436164614461656145",
     {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}),
]


@pytest.mark.parametrize("hexstr, expected", VECTORS)
def test_decode(hexstr, expected):
    buf = bytes.fromhex(hexstr)
    assert cbor.loads(buf) == expected


def test_decode_rejects_trailing_bytes():
    # "01" then garbage. `loads` should refuse; `loads_with_rest` should return
    # the garbage so the caller can do something useful with it.
    buf = bytes.fromhex("01" + "ff")
    with pytest.raises(cbor.CBORDecodeError):
        cbor.loads(buf)

    value, rest = cbor.loads_with_rest(buf)
    assert value == 1
    assert rest == b"\xff"


def test_indefinite_byte_string():
    # 0x5f .. 0xff = indefinite-length byte string of two chunks "010203", "0405".
    buf = bytes.fromhex("5f43010203420405ff")
    assert cbor.loads(buf) == b"\x01\x02\x03\x04\x05"


def test_indefinite_text_string():
    buf = bytes.fromhex("7f657374726561646d696e67ff")  # "streaming"
    assert cbor.loads(buf) == "streaming"


def test_indefinite_array():
    buf = bytes.fromhex("9f018202039f0405ffff")  # [1, [2, 3], [4, 5]]
    assert cbor.loads(buf) == [1, [2, 3], [4, 5]]


def test_indefinite_map():
    # {"a": 1, "b": [2, 3]} indefinite-length.
    buf = bytes.fromhex("bf61610161629f0203ffff")
    assert cbor.loads(buf) == {"a": 1, "b": [2, 3]}


def test_simple_values():
    assert cbor.loads(bytes.fromhex("f4")) is False
    assert cbor.loads(bytes.fromhex("f5")) is True
    assert cbor.loads(bytes.fromhex("f6")) is None
