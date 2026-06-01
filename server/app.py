"""Minimal Flask Relying Party.

Endpoints:
  GET  /                        : serves client/index.html
  GET  /static/<path>           : serves client/* assets
  POST /register/begin          : returns PublicKeyCredentialCreationOptions (JSON)
  POST /register/complete       : verifies attestation, stores the credential
  POST /authenticate/begin      : returns PublicKeyCredentialRequestOptions (JSON)
  POST /authenticate/complete   : verifies the assertion, bumps signCount

The credential store is an in-memory dict keyed by base64url credentialId.
Sessions (challenge state across the two-leg ceremony) are kept in flask.session.

All `bytes` ↔ JSON conversions go through base64url-without-padding to match
WebAuthn's wire format. We do that ourselves rather than rely on a library so
the dataflow stays visible.
"""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session

from . import verify

CLIENT_DIR = Path(__file__).resolve().parent.parent / "client"

RP_ID = "localhost"
RP_NAME = "WebAuthn the Hard Way"
ORIGIN = "http://localhost:5000"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# In-memory store: credential_id (bytes) -> StoredCredential.
CREDENTIALS: dict[bytes, verify.StoredCredential] = {}


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    # Sessions store the challenge between begin and complete. The secret_key
    # only protects this transient state; it does not protect credentials.
    app.secret_key = os.environ.get("WEBAUTHN_SECRET", secrets.token_hex(32))

    @app.route("/")
    def index():
        return send_from_directory(CLIENT_DIR, "index.html")

    @app.route("/static/<path:filename>")
    def client_assets(filename):
        return send_from_directory(CLIENT_DIR, filename)

    # ----- registration -----

    @app.post("/register/begin")
    def register_begin():
        body = request.get_json(force=True) or {}
        username = body.get("username", "demo").strip() or "demo"

        # Per WebAuthn the RP picks a 64-bit-ish opaque user.id. We use a fresh
        # 32-byte random ID so demos are stateless; production RPs reuse a stable
        # id tied to the user record.
        user_handle = secrets.token_bytes(16)
        challenge = secrets.token_bytes(32)

        session["reg_challenge"] = b64url_encode(challenge)
        session["reg_user_handle"] = b64url_encode(user_handle)
        session["reg_username"] = username

        options = {
            "rp": {"id": RP_ID, "name": RP_NAME},
            "user": {
                "id": b64url_encode(user_handle),
                "name": username,
                "displayName": username,
            },
            "challenge": b64url_encode(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "timeout": 60_000,
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "required",
                "residentKey": "preferred",
            },
            # The browser auto-deduplicates against allowed credentials. We pass
            # the credentials already registered to this user so the demo does
            # not silently overwrite them.
            "excludeCredentials": [
                {"type": "public-key", "id": b64url_encode(c.credential_id)}
                for c in CREDENTIALS.values()
                if c.user_handle == user_handle
            ],
        }
        return jsonify(options)

    @app.post("/register/complete")
    def register_complete():
        body = request.get_json(force=True) or {}
        client_data_json_b64 = body.get("clientDataJSON")
        attestation_object_b64 = body.get("attestationObject")
        if not client_data_json_b64 or not attestation_object_b64:
            return jsonify({"error": "missing clientDataJSON or attestationObject"}), 400

        client_data_json = b64url_decode(client_data_json_b64)
        attestation_object = b64url_decode(attestation_object_b64)

        challenge_b64 = session.get("reg_challenge")
        user_handle_b64 = session.get("reg_user_handle")
        if not challenge_b64 or not user_handle_b64:
            return jsonify({"error": "no registration session in progress"}), 400

        challenge = b64url_decode(challenge_b64)
        user_handle = b64url_decode(user_handle_b64)

        try:
            result = verify.verify_registration(
                client_data_json=client_data_json,
                attestation_object=attestation_object,
                expected_challenge=challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                require_user_verification=True,
            )
        except Exception as e:
            return jsonify({"error": f"registration verification failed: {e}"}), 400

        if result.credential_id in CREDENTIALS:
            return jsonify({"error": "credential already registered"}), 409

        CREDENTIALS[result.credential_id] = verify.StoredCredential(
            credential_id=result.credential_id,
            public_key_cbor=result.public_key_cbor,
            sign_count=result.sign_count,
            aaguid=result.aaguid,
            user_handle=user_handle,
        )

        # Clear the registration challenge so it cannot be replayed.
        session.pop("reg_challenge", None)

        return jsonify(
            {
                "ok": True,
                "credentialId": b64url_encode(result.credential_id),
                "aaguid": result.aaguid.hex(),
                "alg": result.public_key.alg,
                "backupEligible": result.backup_eligible,
                "backupState": result.backup_state,
            }
        )

    # ----- authentication -----

    @app.post("/authenticate/begin")
    def authenticate_begin():
        challenge = secrets.token_bytes(32)
        session["auth_challenge"] = b64url_encode(challenge)

        options = {
            "rpId": RP_ID,
            "challenge": b64url_encode(challenge),
            "timeout": 60_000,
            "userVerification": "required",
            "allowCredentials": [
                {"type": "public-key", "id": b64url_encode(c.credential_id)} for c in CREDENTIALS.values()
            ],
        }
        return jsonify(options)

    @app.post("/authenticate/complete")
    def authenticate_complete():
        body = request.get_json(force=True) or {}
        cred_id_b64 = body.get("credentialId")
        client_data_json_b64 = body.get("clientDataJSON")
        authenticator_data_b64 = body.get("authenticatorData")
        signature_b64 = body.get("signature")

        if not all([cred_id_b64, client_data_json_b64, authenticator_data_b64, signature_b64]):
            return jsonify({"error": "missing fields"}), 400

        cred_id = b64url_decode(cred_id_b64)
        client_data_json = b64url_decode(client_data_json_b64)
        authenticator_data = b64url_decode(authenticator_data_b64)
        signature = b64url_decode(signature_b64)

        challenge_b64 = session.get("auth_challenge")
        if not challenge_b64:
            return jsonify({"error": "no authentication session in progress"}), 400
        challenge = b64url_decode(challenge_b64)

        stored = CREDENTIALS.get(cred_id)
        if stored is None:
            return jsonify({"error": "unknown credential"}), 404

        try:
            result = verify.verify_assertion(
                client_data_json=client_data_json,
                authenticator_data=authenticator_data,
                signature=signature,
                stored=stored,
                expected_challenge=challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                require_user_verification=True,
            )
        except Exception as e:
            return jsonify({"error": f"assertion verification failed: {e}"}), 400

        stored.sign_count = result.new_sign_count
        session.pop("auth_challenge", None)

        return jsonify(
            {
                "ok": True,
                "userHandle": b64url_encode(stored.user_handle),
                "newSignCount": result.new_sign_count,
                "userVerified": result.user_verified,
                "backupState": result.backup_state,
            }
        )

    @app.get("/credentials")
    def list_credentials():
        # Debug helper: list what is registered. Not part of the WebAuthn protocol.
        return jsonify(
            [
                {
                    "credentialId": b64url_encode(c.credential_id),
                    "aaguid": c.aaguid.hex(),
                    "signCount": c.sign_count,
                    "userHandle": b64url_encode(c.user_handle),
                }
                for c in CREDENTIALS.values()
            ]
        )

    @app.post("/credentials/reset")
    def reset_credentials():
        CREDENTIALS.clear()
        return jsonify({"ok": True})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
