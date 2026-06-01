# WebAuthn the Hard Way

Build a WebAuthn Relying Party from scratch. No `py_webauthn`, no `fido2`, no SimpleWebAuthn. CBOR, COSE, attestation parsing, signature verification: all by hand.

This is the educational counterpart to "Kubernetes the Hard Way" for the WebAuthn / Passkey stack. The goal is not a production RP. The goal is to make the byte layout, the ceremony state machine, and the verification logic visible.

## What you build

A Flask Relying Party (`localhost:5000`) that:

1. Registers a credential via `navigator.credentials.create()`.
2. Parses the `attestationObject` (CBOR) by hand.
3. Parses the `authenticatorData` byte layout by hand.
4. Decodes the `COSE_Key` into an ECDSA P-256 (or RSA) public key by hand.
5. Verifies the `packed` attestation signature.
6. Authenticates via `navigator.credentials.get()` and verifies the assertion signature.

The only external dependencies are `flask` (HTTP server) and `cryptography` (the actual ECDSA / RSA primitives). Everything WebAuthn-specific is local code.

## Why "the hard way"

Existing tutorials hand you `py_webauthn.verify_registration_response()` and call it a day. That skips:

- **CBOR**: RFC 8949 wire format. Major types, additional info bits, why `0xa3` means "map with 3 pairs".
- **COSE**: RFC 8152 key encoding. Why `{1: 2, 3: -7, -1: 1, -2: <x>, -3: <y>}` is an ECDSA P-256 public key.
- **authData layout**: 37 bytes minimum, then variable. `rpIdHash (32) | flags (1) | signCount (4) | [AAGUID (16) | credIdLen (2) | credId | credPublicKey]`.
- **Attestation formats**: `none`, `packed` (self vs x5c), `fido-u2f`, `tpm`, `apple`. Each is a different sub-protocol on top.
- **Signature base**: `authenticatorData || SHA256(clientDataJSON)`. Concatenation matters; many bugs live here.

Reading the spec ([WebAuthn L3](https://www.w3.org/TR/webauthn-3/)) and walking the bytes is the only way the picture sticks.

## Repository layout

```text
.
├── README.md
├── run.sh                       # venv + flask up, open localhost
├── pyproject.toml               # deps: flask, cryptography
├── server/
│   ├── app.py                   # Flask RP: /register/{begin,complete}, /authenticate/{begin,complete}
│   ├── cbor.py                  # RFC 8949 decoder (subset). Zero deps.
│   ├── cose.py                  # RFC 8152 COSE_Key -> cryptography public key
│   ├── parsers.py               # clientDataJSON, authenticatorData, attestationObject
│   ├── verify.py                # WebAuthn L3 §7.1 (register) and §7.2 (authenticate)
│   └── attestation/
│       ├── __init__.py
│       ├── none.py              # fmt="none"
│       └── packed.py            # fmt="packed" self + x5c
├── client/
│   ├── index.html               # register + authenticate UI
│   ├── register.js              # navigator.credentials.create()
│   └── authenticate.js          # navigator.credentials.get()
└── tests/
    ├── test_cbor.py             # RFC 8949 Appendix A test vectors
    └── test_cose.py             # COSE_Key round-trip
```

## Quick start

```bash
./run.sh
# open http://localhost:5000 in Chrome / Safari / Firefox
# click "Register" -> Touch ID / Windows Hello / YubiKey
# click "Authenticate" -> same authenticator
```

The terminal shows the parsed `authData` field-by-field, the decoded COSE key, and the verification result. That is the point of this repo.

## Reading order

If you want to learn rather than just run:

1. `server/cbor.py` (RFC 8949). Start here. CBOR is the foundation.
2. `tests/test_cbor.py` (RFC 8949 Appendix A). Confirm the decoder matches the spec's test vectors.
3. `server/cose.py` (RFC 8152). COSE = CBOR + key conventions.
4. `server/parsers.py`. The byte-pulling. This is the layer most tutorials skip.
5. `server/attestation/packed.py`. The signature you verify is over `authData || clientDataHash`. Concatenation is load-bearing.
6. `server/verify.py`. The 19-step registration and 22-step authentication procedures, written out.

## Limitations (on purpose)

- In-memory credential store, no database.
- Attestation: `none` + `packed` only. Skips `fido-u2f`, `tpm`, `android-key`, `android-safetynet`, `apple`. (These are interesting but additive; the core ceremony is identical.)
- Algorithms: ES256 (`-7`) + RS256 (`-257`). No EdDSA / RS1.
- No metadata service (FIDO MDS) integration. AAGUID is parsed but not cross-referenced.
- Localhost only. WebAuthn requires HTTPS for non-localhost RP IDs; the spec carves out `localhost` as the one exception, which keeps the demo dependency-free.

## References

- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 8152: COSE](https://www.rfc-editor.org/rfc/rfc8152)
- [RFC 9052: COSE (revised)](https://www.rfc-editor.org/rfc/rfc9052)
- [FIDO Alliance: Passkey](https://fidoalliance.org/passkeys/)

## License

MIT.
