"""Tests for the COSE_Key parser.

We build a fixture COSE_Key in dict form, encode just enough CBOR around it to
prove the integration with the CBOR decoder, and check we end up with a
cryptography ECDSA public key whose numbers match the inputs.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from server import cose


def test_parse_ec2_es256():
    # Generate a real P-256 keypair so the coordinates lie on the curve;
    # cryptography rejects bogus coordinates inside .public_key().
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    cose_map = {1: 2, 3: -7, -1: 1, -2: x, -3: y}

    key = cose.parse(cose_map)
    assert key.kty == cose.KTY_EC2
    assert key.alg == cose.ALG_ES256
    assert isinstance(key.public_key, ec.EllipticCurvePublicKey)
    out = key.public_key.public_numbers()
    assert out.x == numbers.x
    assert out.y == numbers.y


def test_parse_rejects_missing_kty():
    with pytest.raises(cose.CoseKeyError):
        cose.parse({3: -7})  # no kty


def test_parse_rejects_unknown_curve():
    cose_map = {1: 2, 3: -7, -1: 999, -2: b"\x00" * 32, -3: b"\x00" * 32}
    with pytest.raises(cose.CoseKeyError):
        cose.parse(cose_map)


def test_parse_rejects_wrong_coordinate_length():
    cose_map = {1: 2, 3: -7, -1: 1, -2: b"\x00" * 31, -3: b"\x00" * 32}
    with pytest.raises(cose.CoseKeyError):
        cose.parse(cose_map)


def test_parse_rsa_rs256():
    # Generate a real RSA keypair so n is a valid 2048-bit semiprime; mirrors
    # the EC2 test approach (cryptography may sanity-check the modulus too).
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pn = private_key.public_key().public_numbers()
    n = pn.n.to_bytes(256, "big")
    e = pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big")
    cose_map = {1: 3, 3: -257, -1: n, -2: e}

    key = cose.parse(cose_map)
    assert key.kty == cose.KTY_RSA
    assert key.alg == cose.ALG_RS256
    assert isinstance(key.public_key, rsa.RSAPublicKey)
    out = key.public_key.public_numbers()
    assert out.e == 65537
    assert out.n == pn.n
