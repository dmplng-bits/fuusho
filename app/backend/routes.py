"""
Flask Blueprint: the entire fuusho HTTP API.

  POST   /api/pair/start       -> start a QR pairing session; returns the
                                  payload the app scans or pastes
  GET    /pair                 -> human-facing page rendering that same
                                  payload as a scannable QR (auto-refreshes)
  POST   /api/pair/complete    -> finish pairing: decrypt the app's
                                  ECDH-wrapped registration and store the
                                  device (see backend/pairing.py for the
                                  full handshake)
  GET    /api/devices          -> registered devices (names + token prefixes
                                  only — never keys)
  DELETE /api/devices/<token>  -> revoke one device
  POST   /api/notify           -> deliver an E2E-encrypted push to every
                                  paired device (also handy for curl)

There is no standing shared secret gating registration — each pairing
session is single-use, expires in ~90s, and is bootstrapped by an
out-of-band QR (or a pasted copy of the same payload), which is what
actually authenticates it. See backend/pairing.py for the security model.

Device record shape (state category "devices"):
  {"token": <64+ hex chars from APNs>, "name": "Alice's iPhone",
   "encryptionKey": <base64, server-side copy>, "registeredAt": iso8601,
   "apnsEnvironment": "development" | "production" (absent on records
   registered before the app reported it; those use the legacy
   APNS_USE_SANDBOX default at send time)}
"""

import base64
import hmac
import json
import os
import re
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from . import apns_client, notification_dispatch, pairing, state_store

api_blueprint = Blueprint("api", __name__)

# Where the app should point after scanning — the container only knows its
# own internal host, not the LAN/public address people actually reach it at.
PUBLIC_SERVER_URL = os.environ.get("PUBLIC_SERVER_URL", "http://localhost:8090")
# When set, /api/notify requires this in the X-Internal-Secret header —
# stops anyone on the LAN from pushing arbitrary (phishing) notifications
# to your devices. Give this to your own scheduler/automation, nothing else.
INTERNAL_API_SECRET = os.environ.get("INTERNAL_API_SECRET")
APNS_DEVICE_TOKEN_PATTERN = re.compile(r"^[0-9a-fA-F]{64,200}$")
MAXIMUM_REGISTERED_DEVICES = 20
MAXIMUM_DEVICE_NAME_LENGTH = 60
MAXIMUM_NOTIFICATION_TITLE_LENGTH = 100
MAXIMUM_NOTIFICATION_BODY_LENGTH = 2000


def secrets_match(presented_secret, expected_secret):
    """Constant-time comparison — never compare secrets with == (timing
    side channel)."""
    return hmac.compare_digest(
        (presented_secret or "").encode(), (expected_secret or "").encode()
    )


def summarize_device_for_listing(device):
    return {
        "name": device.get("name", ""),
        "tokenPrefix": device["token"][:8],
        "registeredAt": device.get("registeredAt", ""),
        "apnsEnvironment": apns_client.environment_for_device(device),
    }


@api_blueprint.post("/api/pair/start")
def post_pair_start():
    return jsonify(pairing.create_pairing_session(PUBLIC_SERVER_URL))


@api_blueprint.get("/pair")
def get_pair_page():
    session = pairing.create_pairing_session(PUBLIC_SERVER_URL)
    payload_json = json.dumps(session)
    qr_data_uri = pairing.render_qr_data_uri(payload_json)
    return f"""<!doctype html>
<html><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="70">
  <title>Pair a device — fuusho</title>
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif; background: #0b0c10; color: #f1f1f4;
           display: flex; flex-direction: column; align-items: center; padding: 48px 24px; }}
    img {{ width: 260px; height: 260px; border-radius: 12px; background: #fff; padding: 12px; }}
    code {{ font-family: ui-monospace, monospace; font-size: 12px; color: #9a9eb1; word-break: break-all;
            display: block; max-width: 420px; margin-top: 20px; text-align: left; }}
    p {{ color: #9a9eb1; font-size: 14px; }}
  </style>
</head><body>
  <h1 style="font-size:18px;">Scan this in your app's pairing screen</h1>
  <img src="{qr_data_uri}" alt="Pairing QR code">
  <p>Expires in {pairing.PAIRING_SESSION_TTL_SECONDS}s — this page refreshes itself before that happens.</p>
  <p>No camera? Paste this into "Enter Manually" instead:</p>
  <code>{payload_json}</code>
</body></html>"""


@api_blueprint.post("/api/pair/complete")
def post_pair_complete():
    request_body = request.get_json(force=True)
    try:
        device_registration = pairing.complete_pairing_session(
            request_body.get("token", ""),
            request_body.get("appPublicKey", ""),
            request_body.get("nonce", ""),
            request_body.get("ciphertext", ""),
        )
    except pairing.PairingSessionError as pairing_error:
        return jsonify({"error": str(pairing_error)}), 400

    device_token = (device_registration.get("apnsDeviceTokenHex") or "").strip()
    if not APNS_DEVICE_TOKEN_PATTERN.match(device_token):
        return jsonify({"error": "token must be the hex APNs device token"}), 400
    device_name = (device_registration.get("deviceName") or "unnamed device").strip()[:MAXIMUM_DEVICE_NAME_LENGTH]

    push_encryption_key_base64 = device_registration.get("pushEncryptionKey", "")
    try:
        key_is_256_bit = len(base64.b64decode(push_encryption_key_base64)) == 32
    except Exception:
        key_is_256_bit = False
    if not key_is_256_bit:
        return jsonify({"error": "pushEncryptionKey must be 32 raw bytes, base64-encoded"}), 400

    devices = state_store.read_state("devices")

    # Re-pairing a known token (reinstall, name change) rotates the key
    # rather than duplicating the device.
    devices = [device for device in devices if device["token"] != device_token]
    if len(devices) >= MAXIMUM_REGISTERED_DEVICES:
        return jsonify({"error": "device limit reached — revoke one first"}), 409

    device_record = {
        "token": device_token,
        "name": device_name,
        "encryptionKey": push_encryption_key_base64,
        "registeredAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # The app reports which APNs gateway issued its token (Xcode installs =
    # development, TestFlight/App Store = production). Unknown values are
    # dropped rather than stored: send-time falls back to the legacy default.
    reported_environment = device_registration.get("apnsEnvironment")
    if reported_environment in apns_client.KNOWN_APNS_ENVIRONMENTS:
        device_record["apnsEnvironment"] = reported_environment
    devices.append(device_record)
    state_store.write_state("devices", devices)

    # Unlike a naive registration flow, no key crosses the wire here — the
    # app already generated its own and only told us about it, encrypted.
    return jsonify({"apnsConfigured": apns_client.apns_is_configured()})


@api_blueprint.get("/api/devices")
def get_registered_devices():
    return jsonify({
        "devices": [
            summarize_device_for_listing(device)
            for device in state_store.read_state("devices")
        ],
        "apnsConfigured": apns_client.apns_is_configured(),
    })


@api_blueprint.delete("/api/devices/<token_prefix>")
def delete_device(token_prefix):
    devices = state_store.read_state("devices")
    remaining_devices = [
        device for device in devices if not device["token"].startswith(token_prefix)
    ]
    if len(remaining_devices) == len(devices):
        return jsonify({"error": "no device with that token prefix"}), 404
    state_store.write_state("devices", remaining_devices)
    return jsonify({"ok": True})


@api_blueprint.post("/api/notify")
def post_notify():
    if INTERNAL_API_SECRET and not secrets_match(
        request.headers.get("X-Internal-Secret"), INTERNAL_API_SECRET
    ):
        return jsonify({"error": "internal secret required"}), 403
    request_body = request.get_json(force=True)
    notification_body = (request_body.get("body") or "").strip()[:MAXIMUM_NOTIFICATION_BODY_LENGTH]
    if not notification_body:
        return jsonify({"error": "body is required"}), 400
    delivered = notification_dispatch.dispatch_notification(
        (request_body.get("title") or "Notification").strip()[:MAXIMUM_NOTIFICATION_TITLE_LENGTH],
        notification_body,
        request_body.get("priority", "default"),
        request_body.get("tags", ""),
    )
    return (jsonify({"ok": True}), 200) if delivered else (jsonify({"error": "no channel delivered"}), 502)
