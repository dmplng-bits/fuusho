
"""
Unit tests for the fuusho server: pairing (X25519/ECDH handshake),
apns_client (encryption, JWT, payload shape), notification_dispatch
(fan-out isolation), and the full HTTP API in fuusho/routes.py.

Run from the project root:
    python -m pytest tests/ -q
"""

import base64
import json
import secrets
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask

sys.path.insert(0, str(Path(__file__).parent.parent))

from fuusho import apns_client, notification_dispatch, pairing, state_store  # noqa: E402
from fuusho.routes import api_blueprint  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(state_store, "DATABASE_FILE_PATH", str(tmp_path / "test.sqlite3"))


@pytest.fixture
def api_client():
    flask_app = Flask(__name__)
    flask_app.register_blueprint(api_blueprint)
    return flask_app.test_client()


VALID_DEVICE_TOKEN = "ab" * 32  # 64 hex chars, like a real APNs device token
VALID_PUSH_KEY = base64.b64encode(b"0" * 32).decode()


def encrypt_pairing_payload(session, plaintext_dict):
    """Mimics what a client does after scanning a pairing QR: generate an
    ephemeral X25519 keypair, derive the transport key exactly the way
    pairing.py does, and AES-256-GCM-encrypt the registration payload."""
    app_private_key = X25519PrivateKey.generate()
    app_public_key_base64 = base64.b64encode(
        app_private_key.public_key().public_bytes_raw()
    ).decode()
    server_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(session["pub"]))
    shared_secret = app_private_key.exchange(server_public_key)
    transport_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=session["token"].encode(), info=pairing.HKDF_INFO,
    ).derive(shared_secret)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(transport_key).encrypt(nonce, json.dumps(plaintext_dict).encode(), None)
    return {
        "token": session["token"],
        "appPublicKey": app_public_key_base64,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def make_registration_payload(apns_device_token_hex=VALID_DEVICE_TOKEN, device_name="iPhone", push_encryption_key=None, apns_environment=None):
    registration_payload = {
        "apnsDeviceTokenHex": apns_device_token_hex,
        "deviceName": device_name,
        "pushEncryptionKey": push_encryption_key or VALID_PUSH_KEY,
    }
    if apns_environment is not None:
        registration_payload["apnsEnvironment"] = apns_environment
    return registration_payload


def complete_pairing_via_http(api_client, **payload_overrides):
    start_response = api_client.post("/api/pair/start")
    session = start_response.get_json()
    wire_message = encrypt_pairing_payload(session, make_registration_payload(**payload_overrides))
    return api_client.post("/api/pair/complete", json=wire_message)


# ------------------------------------------------------------- apns_client

class TestEncryption:
    def test_round_trip_decrypts_to_original_payload(self):
        device_key = apns_client.generate_device_encryption_key()
        encrypted_blob = base64.b64decode(
            apns_client.encrypt_notification_payload(device_key, "Reminder", "Apply to 2 jobs")
        )
        nonce = encrypted_blob[: apns_client.AES_GCM_NONCE_LENGTH_BYTES]
        ciphertext_with_tag = encrypted_blob[apns_client.AES_GCM_NONCE_LENGTH_BYTES:]
        plaintext = AESGCM(base64.b64decode(device_key)).decrypt(nonce, ciphertext_with_tag, None)
        assert json.loads(plaintext) == {"title": "Reminder", "body": "Apply to 2 jobs"}

    def test_each_device_key_is_unique_and_256_bit(self):
        first_key, second_key = (
            apns_client.generate_device_encryption_key(),
            apns_client.generate_device_encryption_key(),
        )
        assert first_key != second_key
        assert len(base64.b64decode(first_key)) == 32

    def test_wrong_key_cannot_decrypt(self):
        encrypted_blob = base64.b64decode(
            apns_client.encrypt_notification_payload(
                apns_client.generate_device_encryption_key(), "t", "b"
            )
        )
        wrong_key = base64.b64decode(apns_client.generate_device_encryption_key())
        with pytest.raises(Exception):
            AESGCM(wrong_key).decrypt(encrypted_blob[:12], encrypted_blob[12:], None)


class TestProviderToken:
    def test_jwt_is_es256_signed_with_key_id_header(self, tmp_path, monkeypatch):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        private_key = ec.generate_private_key(ec.SECP256R1())
        key_path = tmp_path / "AuthKey_TEST123456.p8"
        key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        monkeypatch.setattr(apns_client, "APNS_KEY_PATH", str(key_path))
        monkeypatch.setattr(apns_client, "APNS_KEY_ID", "TEST123456")
        monkeypatch.setattr(apns_client, "APNS_TEAM_ID", "TEAM567890")
        monkeypatch.setattr(apns_client, "_cached_provider_tokens_by_key_id", {})

        provider_token = apns_client.get_provider_token()
        assert pyjwt.get_unverified_header(provider_token) == {"alg": "ES256", "typ": "JWT", "kid": "TEST123456"}
        decoded_claims = pyjwt.decode(provider_token, private_key.public_key(), algorithms=["ES256"])
        assert decoded_claims["iss"] == "TEAM567890"

    def test_apns_unconfigured_without_env(self, monkeypatch):
        monkeypatch.setattr(apns_client, "APNS_KEY_PATH", None)
        assert apns_client.apns_is_configured() is False


# --------------------------------------------------- notification_dispatch

class TestDispatchFanOut:
    def test_delivers_to_every_registered_device(self, monkeypatch):
        key = apns_client.generate_device_encryption_key()
        state_store.write_state("devices", [
            {"token": VALID_DEVICE_TOKEN, "name": "iPhone", "encryptionKey": key},
            {"token": "bb" * 32, "name": "second phone", "encryptionKey": key},
        ])
        monkeypatch.setattr(notification_dispatch.apns_client, "apns_is_configured", lambda: True)
        apns_sends = []
        monkeypatch.setattr(
            notification_dispatch.apns_client, "send_encrypted_notification",
            lambda device, title, body: apns_sends.append(device["name"]),
        )
        assert notification_dispatch.dispatch_notification("t", "b") is True
        assert apns_sends == ["iPhone", "second phone"]

    def test_one_stale_device_does_not_block_the_next(self, monkeypatch):
        key = apns_client.generate_device_encryption_key()
        state_store.write_state("devices", [
            {"token": "aa" * 32, "name": "old phone", "encryptionKey": key},
            {"token": "bb" * 32, "name": "new phone", "encryptionKey": key},
        ])
        monkeypatch.setattr(notification_dispatch.apns_client, "apns_is_configured", lambda: True)

        def send_failing_for_old_phone(device, title, body):
            if device["name"] == "old phone":
                raise RuntimeError("410 Unregistered")
        monkeypatch.setattr(
            notification_dispatch.apns_client, "send_encrypted_notification",
            send_failing_for_old_phone,
        )
        assert notification_dispatch.dispatch_notification("t", "b") is True

    def test_apns_unconfigured_returns_false(self, monkeypatch):
        monkeypatch.setattr(notification_dispatch.apns_client, "apns_is_configured", lambda: False)
        assert notification_dispatch.dispatch_notification("t", "b") is False


# ------------------------------------------------------------------ routes

class TestPairingSession:
    """Unit-level tests for fuusho/pairing.py's ECDH handshake, independent
    of Flask — the property under test is that the QR's public key, not a
    shared secret, is what authenticates the exchange."""

    def test_round_trip_recovers_original_payload(self):
        session = pairing.create_pairing_session("http://localhost:8090")
        wire_message = encrypt_pairing_payload(session, {"hello": "world"})
        recovered = pairing.complete_pairing_session(
            wire_message["token"], wire_message["appPublicKey"],
            wire_message["nonce"], wire_message["ciphertext"],
        )
        assert recovered == {"hello": "world"}

    def test_token_is_single_use(self):
        session = pairing.create_pairing_session("http://localhost:8090")
        wire_message = encrypt_pairing_payload(session, {"hello": "world"})
        pairing.complete_pairing_session(
            wire_message["token"], wire_message["appPublicKey"],
            wire_message["nonce"], wire_message["ciphertext"],
        )
        with pytest.raises(pairing.PairingSessionError):
            pairing.complete_pairing_session(
                wire_message["token"], wire_message["appPublicKey"],
                wire_message["nonce"], wire_message["ciphertext"],
            )

    def test_expired_session_is_rejected(self, monkeypatch):
        monkeypatch.setattr(pairing, "PAIRING_SESSION_TTL_SECONDS", -1)
        session = pairing.create_pairing_session("http://localhost:8090")
        wire_message = encrypt_pairing_payload(session, {"hello": "world"})
        with pytest.raises(pairing.PairingSessionError):
            pairing.complete_pairing_session(
                wire_message["token"], wire_message["appPublicKey"],
                wire_message["nonce"], wire_message["ciphertext"],
            )

    def test_unknown_token_is_rejected(self):
        with pytest.raises(pairing.PairingSessionError):
            pairing.complete_pairing_session("does-not-exist", "", "", "")

    def test_wrong_app_key_cannot_complete_a_different_session(self):
        session = pairing.create_pairing_session("http://localhost:8090")
        genuine_message = encrypt_pairing_payload(session, {"hello": "world"})
        attacker_private_key = X25519PrivateKey.generate()
        forged_public_key = base64.b64encode(
            attacker_private_key.public_key().public_bytes_raw()
        ).decode()
        with pytest.raises(pairing.PairingSessionError):
            pairing.complete_pairing_session(
                genuine_message["token"], forged_public_key,
                genuine_message["nonce"], genuine_message["ciphertext"],
            )


class TestPairAndRegisterRoutes:
    def test_pair_start_returns_a_fresh_session(self, api_client):
        response = api_client.post("/api/pair/start")
        assert response.status_code == 200
        session = response.get_json()
        assert set(session.keys()) == {"v", "server", "token", "pub", "expiresAt"}

    def test_full_pairing_round_trip_registers_the_device(self, api_client):
        response = complete_pairing_via_http(api_client)
        assert response.status_code == 200
        assert response.get_json() == {"apnsConfigured": False}
        stored_devices = state_store.read_state("devices")
        assert stored_devices[0]["token"] == VALID_DEVICE_TOKEN
        assert stored_devices[0]["encryptionKey"] == VALID_PUSH_KEY
        listing = api_client.get("/api/devices").get_json()["devices"]
        assert listing == [{"name": "iPhone", "tokenPrefix": VALID_DEVICE_TOKEN[:8],
                            "registeredAt": stored_devices[0]["registeredAt"],
                            "apnsEnvironment": apns_client.LEGACY_DEFAULT_ENVIRONMENT}]

    def test_repairing_rotates_key_without_duplicating(self, api_client):
        complete_pairing_via_http(api_client)
        second_key = base64.b64encode(b"1" * 32).decode()
        complete_pairing_via_http(api_client, push_encryption_key=second_key)
        stored_devices = state_store.read_state("devices")
        assert len(stored_devices) == 1
        assert stored_devices[0]["encryptionKey"] == second_key

    def test_rejects_malformed_device_token(self, api_client):
        assert complete_pairing_via_http(
            api_client, apns_device_token_hex="not-a-token"
        ).status_code == 400

    def test_rejects_wrong_size_encryption_key(self, api_client):
        assert complete_pairing_via_http(
            api_client, push_encryption_key=base64.b64encode(b"too-short").decode()
        ).status_code == 400

    def test_completing_with_an_already_used_token_fails(self, api_client):
        start_response = api_client.post("/api/pair/start")
        session = start_response.get_json()
        wire_message = encrypt_pairing_payload(session, make_registration_payload())
        api_client.post("/api/pair/complete", json=wire_message)  # consumes it
        replay_response = api_client.post("/api/pair/complete", json=wire_message)
        assert replay_response.status_code == 400

    def test_pair_page_renders_a_scannable_qr(self, api_client):
        response = api_client.get("/pair")
        assert response.status_code == 200
        assert b"data:image/png;base64," in response.data


class TestPerDeviceApnsEnvironment:
    """TestFlight/App Store installs hold production tokens while Xcode
    installs hold sandbox ones; each device's push must go through the
    gateway that issued its token, with a key that gateway accepts."""

    def test_registration_stores_reported_environment(self, api_client):
        response = complete_pairing_via_http(api_client, apns_environment="production")
        assert response.status_code == 200
        stored_device = state_store.read_state("devices")[0]
        assert stored_device["apnsEnvironment"] == "production"

    def test_unknown_environment_value_is_dropped(self, api_client):
        response = complete_pairing_via_http(api_client, apns_environment="staging")
        assert response.status_code == 200
        assert "apnsEnvironment" not in state_store.read_state("devices")[0]

    def test_device_listing_reports_environment(self, api_client):
        complete_pairing_via_http(api_client, apns_environment="production")
        listed_devices = api_client.get("/api/devices").get_json()["devices"]
        assert listed_devices[0]["apnsEnvironment"] == "production"

    def test_legacy_device_falls_back_to_server_default(self, monkeypatch):
        monkeypatch.setattr(apns_client, "LEGACY_DEFAULT_ENVIRONMENT", "development")
        assert apns_client.environment_for_device({"token": "aa" * 32}) == "development"
        monkeypatch.setattr(apns_client, "LEGACY_DEFAULT_ENVIRONMENT", "production")
        assert apns_client.environment_for_device({"token": "aa" * 32}) == "production"

    def test_reported_environment_wins_over_server_default(self, monkeypatch):
        monkeypatch.setattr(apns_client, "LEGACY_DEFAULT_ENVIRONMENT", "development")
        assert apns_client.environment_for_device(
            {"token": "aa" * 32, "apnsEnvironment": "production"}
        ) == "production"

    def test_production_key_preferred_for_production_devices(self, monkeypatch):
        monkeypatch.setattr(apns_client, "APNS_KEY_PATH", "/keys/sandbox.p8")
        monkeypatch.setattr(apns_client, "APNS_KEY_ID", "SANDBOX123")
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_PATH", "/keys/prod.p8")
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_ID", "PROD456789")
        assert apns_client.signing_key_for_environment("production") == ("/keys/prod.p8", "PROD456789")
        assert apns_client.signing_key_for_environment("development") == ("/keys/sandbox.p8", "SANDBOX123")

    def test_production_falls_back_to_main_key_when_no_dedicated_key(self, monkeypatch):
        monkeypatch.setattr(apns_client, "APNS_KEY_PATH", "/keys/allscope.p8")
        monkeypatch.setattr(apns_client, "APNS_KEY_ID", "ALLSCOPE12")
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_PATH", None)
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_ID", None)
        assert apns_client.signing_key_for_environment("production") == ("/keys/allscope.p8", "ALLSCOPE12")

    def test_send_routes_to_gateway_matching_device_environment(self, monkeypatch):
        requested_urls = []

        class FakeResponse:
            headers = {"apns-id": "test-apns-id"}
            def raise_for_status(self):
                pass

        class FakeHttpClient:
            def __init__(self, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *exc_info):
                return False
            def post(self, url, **kwargs):
                requested_urls.append(url)
                return FakeResponse()

        import httpx
        monkeypatch.setattr(httpx, "Client", FakeHttpClient)
        monkeypatch.setattr(apns_client, "get_provider_token", lambda environment=None: "jwt")

        device_key = apns_client.generate_device_encryption_key()
        apns_client.send_encrypted_notification(
            {"token": "aa" * 32, "encryptionKey": device_key, "apnsEnvironment": "production"},
            "t", "b",
        )
        apns_client.send_encrypted_notification(
            {"token": "bb" * 32, "encryptionKey": device_key, "apnsEnvironment": "development"},
            "t", "b",
        )
        assert requested_urls == [
            "https://api.push.apple.com/3/device/" + "aa" * 32,
            "https://api.sandbox.push.apple.com/3/device/" + "bb" * 32,
        ]

    def test_provider_tokens_cached_per_signing_key(self, tmp_path, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        def write_key(filename):
            key_path = tmp_path / filename
            key_path.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            return str(key_path)

        monkeypatch.setattr(apns_client, "APNS_TEAM_ID", "TEAM567890")
        monkeypatch.setattr(apns_client, "APNS_KEY_PATH", write_key("sandbox.p8"))
        monkeypatch.setattr(apns_client, "APNS_KEY_ID", "SANDBOX123")
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_PATH", write_key("prod.p8"))
        monkeypatch.setattr(apns_client, "APNS_PRODUCTION_KEY_ID", "PROD456789")
        monkeypatch.setattr(apns_client, "_cached_provider_tokens_by_key_id", {})

        import jwt as pyjwt
        development_token = apns_client.get_provider_token("development")
        production_token = apns_client.get_provider_token("production")
        assert pyjwt.get_unverified_header(development_token)["kid"] == "SANDBOX123"
        assert pyjwt.get_unverified_header(production_token)["kid"] == "PROD456789"
        # Cached separately: asking again returns the same tokens.
        assert apns_client.get_provider_token("development") == development_token
        assert apns_client.get_provider_token("production") == production_token


class TestDeviceRevocation:
    def test_revoke_device(self, api_client):
        complete_pairing_via_http(api_client)
        assert api_client.delete(f"/api/devices/{VALID_DEVICE_TOKEN[:8]}").status_code == 200
        assert state_store.read_state("devices") == []
        assert api_client.delete("/api/devices/deadbeef").status_code == 404


class TestNotifyEndpoint:
    def test_notify_dispatches_and_reports_ok(self, api_client, monkeypatch):
        dispatched = []
        monkeypatch.setattr(
            "fuusho.routes.notification_dispatch.dispatch_notification",
            lambda title, body, priority, tags: dispatched.append((title, body)) or True,
        )
        response = api_client.post("/api/notify", json={"title": "Deploy done", "body": "Ship it"})
        assert response.status_code == 200
        assert dispatched == [("Deploy done", "Ship it")]

    def test_notify_requires_body(self, api_client):
        assert api_client.post("/api/notify", json={"title": "x"}).status_code == 400

    def test_notify_reports_total_failure_as_502(self, api_client, monkeypatch):
        monkeypatch.setattr(
            "fuusho.routes.notification_dispatch.dispatch_notification", lambda *a: False,
        )
        assert api_client.post("/api/notify", json={"body": "x"}).status_code == 502

    def test_notify_internal_secret_enforced_when_configured(self, api_client, monkeypatch):
        monkeypatch.setenv("INTERNAL_API_SECRET", "scheduler-only")
        monkeypatch.setattr(
            "fuusho.routes.notification_dispatch.dispatch_notification", lambda *a: True,
        )
        assert api_client.post("/api/notify", json={"body": "x"}).status_code == 403
        assert api_client.post(
            "/api/notify", json={"body": "x"}, headers={"X-Internal-Secret": "scheduler-only"},
        ).status_code == 200

    def test_notify_truncates_oversized_content(self, api_client, monkeypatch):
        dispatched = []
        monkeypatch.setattr(
            "fuusho.routes.notification_dispatch.dispatch_notification",
            lambda title, body, priority, tags: dispatched.append((title, body)) or True,
        )
        api_client.post("/api/notify", json={"title": "T" * 500, "body": "B" * 50000})
        assert len(dispatched[0][0]) == 100 and len(dispatched[0][1]) == 2000
