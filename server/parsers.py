"""Parsers for the WebAuthn binary layouts: authenticatorData, attestationObject.

authenticatorData byte layout (WebAuthn L3 §6.1):

    | rpIdHash   (32)  | SHA-256 of the RP ID. Authenticator scopes credentials to this.
    | flags      ( 1)  | bit 0: UP (user present)
                       | bit 2: UV (user verified)
                       | bit 3: BE (backup eligible, "syncable") -- L3 addition
                       | bit 4: BS (backup state, currently backed up) -- L3 addition
                       | bit 6: AT (attested credential data included)
                       | bit 7: ED (extensions included)
    | signCount  ( 4)  | big-endian counter. Anti-cloning hint.
    | [attestedCredentialData if AT]:
        | AAGUID         (16) | authenticator model identifier
        | credIdLength   ( 2) | big-endian
        | credentialId   (var)
        | credentialPublicKey (CBOR / COSE_Key, variable length)
    | [extensions if ED]: CBOR map

attestationObject layout (WebAuthn L3 §6.5):

    A CBOR map with exactly three entries:
      "fmt"      -> text string identifying the attestation format ("none", "packed", ...)
      "authData" -> byte string carrying the authenticatorData above
      "attStmt"  -> CBOR map whose schema depends on fmt

We keep these parsers free of validation logic. They just translate bytes into a
dataclass tree. The verifier (`verify.py`) walks that tree and decides legality.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import cbor, cose

# Flag bits (WebAuthn L3 §6.1). Bit 0 is the least significant.
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80


class ParseError(ValueError):
    pass


@dataclass
class AttestedCredentialData:
    aaguid: bytes  # 16 bytes
    credential_id: bytes
    credential_public_key: cose.CoseKey
    credential_public_key_cbor: bytes  # raw COSE_Key bytes; useful for assertion verification later


@dataclass
class AuthenticatorData:
    rp_id_hash: bytes  # 32 bytes (SHA-256 of RP ID)
    flags: int  # 1 byte
    sign_count: int  # 4 bytes, big-endian
    attested_credential_data: AttestedCredentialData | None
    extensions: dict | None
    raw: bytes  # original bytes; needed when computing signature base later

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & FLAG_BS)

    @property
    def attested(self) -> bool:
        return bool(self.flags & FLAG_AT)

    @property
    def has_extensions(self) -> bool:
        return bool(self.flags & FLAG_ED)


@dataclass
class AttestationObject:
    fmt: str
    auth_data: AuthenticatorData
    att_stmt: dict
    raw_auth_data: bytes  # exact bytes that went into the CBOR map; signature base inputs depend on these


def parse_authenticator_data(buf: bytes) -> AuthenticatorData:
    if len(buf) < 37:
        # 32 + 1 + 4 = 37 minimum (no attested credential data, no extensions).
        raise ParseError(f"authenticatorData too short: {len(buf)} bytes")

    rp_id_hash = bytes(buf[0:32])
    flags = buf[32]
    sign_count = struct.unpack(">I", buf[33:37])[0]

    offset = 37
    attested: AttestedCredentialData | None = None
    extensions: dict | None = None

    if flags & FLAG_AT:
        # Attested credential data is present.
        if len(buf) < offset + 18:
            raise ParseError("authenticatorData truncated before AAGUID + credIdLength")
        aaguid = bytes(buf[offset : offset + 16])
        offset += 16
        cred_id_len = struct.unpack(">H", buf[offset : offset + 2])[0]
        offset += 2
        if len(buf) < offset + cred_id_len:
            raise ParseError(f"authenticatorData truncated inside credentialId (need {cred_id_len})")
        credential_id = bytes(buf[offset : offset + cred_id_len])
        offset += cred_id_len

        # credentialPublicKey is a single CBOR item. Its length is not encoded;
        # we have to parse it and remember how many bytes it consumed, because
        # extensions (another CBOR map) may follow it.
        cose_map, rest = cbor.loads_with_rest(buf[offset:])
        cose_bytes_consumed = (len(buf) - offset) - len(rest)
        cose_bytes = bytes(buf[offset : offset + cose_bytes_consumed])
        offset += cose_bytes_consumed

        cose_key = cose.parse(cose_map)
        attested = AttestedCredentialData(
            aaguid=aaguid,
            credential_id=credential_id,
            credential_public_key=cose_key,
            credential_public_key_cbor=cose_bytes,
        )

    if flags & FLAG_ED:
        # Extensions is one CBOR map. We do not yet validate any extension; we
        # just decode it so the byte cursor reaches the end of the buffer.
        ext_map, rest = cbor.loads_with_rest(buf[offset:])
        if rest:
            raise ParseError(f"authenticatorData has {len(rest)} trailing bytes after extensions")
        if not isinstance(ext_map, dict):
            raise ParseError("authenticatorData extensions field is not a CBOR map")
        extensions = ext_map
        offset = len(buf)
    else:
        if offset != len(buf):
            raise ParseError(
                f"authenticatorData has {len(buf) - offset} trailing bytes but the ED flag is not set"
            )

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        attested_credential_data=attested,
        extensions=extensions,
        raw=bytes(buf),
    )


def parse_attestation_object(buf: bytes) -> AttestationObject:
    """Decode an attestationObject (a 3-key CBOR map)."""
    decoded = cbor.loads(buf)
    if not isinstance(decoded, dict):
        raise ParseError("attestationObject is not a CBOR map")

    try:
        fmt = decoded["fmt"]
        auth_data_bytes = decoded["authData"]
        att_stmt = decoded["attStmt"]
    except KeyError as e:
        raise ParseError(f"attestationObject missing required field: {e}") from None

    if not isinstance(fmt, str):
        raise ParseError(f"attestationObject.fmt is not text, got {type(fmt).__name__}")
    if not isinstance(auth_data_bytes, (bytes, bytearray)):
        raise ParseError("attestationObject.authData is not a byte string")
    if not isinstance(att_stmt, dict):
        raise ParseError("attestationObject.attStmt is not a CBOR map")

    auth_data = parse_authenticator_data(bytes(auth_data_bytes))
    return AttestationObject(
        fmt=fmt,
        auth_data=auth_data,
        att_stmt=att_stmt,
        raw_auth_data=bytes(auth_data_bytes),
    )
