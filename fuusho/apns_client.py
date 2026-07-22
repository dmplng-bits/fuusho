"""
Direct APNs sender with end-to-end-encrypted payloads.

The privacy design (ship-quality, reusable beyond this app):
- Each registered device has its OWN random 256-bit key, created at
  registration and returned to the device exactly once. Revoking a device
  revokes only that device.
- The push Apple relays contains only ciphertext: the visible alert is a
  placeholder, `mutable-content: 1` makes iOS run the app's Notification
  Service Extension, and the extension decrypts `encryptedPayload` with the
  device's key (Keychain) before the banner is shown. Apple sees bytes it
  cannot read, plus unavoidable metadata (which device, when, how often).
- Wire format, must match the Swift side exactly:
    encryptedPayload = base64( AES-256-GCM nonce (12 bytes)
                               || ciphertext || tag (16 bytes) )
    plaintext        = JSON {"title": ..., "body": ...}

Auth is a standard APNs provider token: ES256 JWT signed with the .p8 key
from the Apple Developer portal, cached ~50 minutes (validity is 1 hour).

Configuration (all env):
  APNS_KEY_PATH   path to the mounted AuthKey_XXXXXXXXXX.p8
  APNS_KEY_ID     the 10-char key id from the portal
  APNS_TEAM_ID    the 10-char team id
  APNS_BUNDLE_ID  the app's bundle id (JWT/topic)
  APNS_USE_SANDBOX  legacy default environment, used only for devices that
                    registered before the app started reporting one:
                    "true" = development gateway, unset/false = production
  APNS_PRODUCTION_KEY_PATH / APNS_PRODUCTION_KEY_ID
                    optional second signing key for the production gateway
                    (TestFlight/App Store installs). Needed because a
                    Sandbox-scoped .p8 cannot sign for production; omit if
                    APNS_KEY_PATH's key is All-scoped.
Unset config leaves APNs disabled — and with it all notification delivery.

Per-device environment: the app reports "apnsEnvironment"
("development" for Xcode/simulator installs, "production" for
TestFlight/App Store) at registration, and each push goes through that
device's gateway with the matching key — a TestFlight install and an
Xcode install can coexist on the same server. Devices with no stored
environment fall back to the APNS_USE_SANDBOX legacy default.
"""

import base64
import json
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APNS_KEY_PATH = os.environ.get("APNS_KEY_PATH")
APNS_KEY_ID = os.environ.get("APNS_KEY_ID")
APNS_TEAM_ID = os.environ.get("APNS_TEAM_ID")
APNS_BUNDLE_ID = os.environ.get("APNS_BUNDLE_ID")
APNS_USE_SANDBOX = os.environ.get("APNS_USE_SANDBOX", "").lower() == "true"
APNS_PRODUCTION_KEY_PATH = os.environ.get("APNS_PRODUCTION_KEY_PATH")
APNS_PRODUCTION_KEY_ID = os.environ.get("APNS_PRODUCTION_KEY_ID")

DEVELOPMENT_ENVIRONMENT = "development"
PRODUCTION_ENVIRONMENT = "production"
KNOWN_APNS_ENVIRONMENTS = {DEVELOPMENT_ENVIRONMENT, PRODUCTION_ENVIRONMENT}
APNS_GATEWAY_BY_ENVIRONMENT = {
    DEVELOPMENT_ENVIRONMENT: "https://api.sandbox.push.apple.com",
    PRODUCTION_ENVIRONMENT: "https://api.push.apple.com",
}
LEGACY_DEFAULT_ENVIRONMENT = (
    DEVELOPMENT_ENVIRONMENT if APNS_USE_SANDBOX else PRODUCTION_ENVIRONMENT
)
PROVIDER_TOKEN_REFRESH_SECONDS = 50 * 60  # APNs allows 1h; refresh early
AES_GCM_NONCE_LENGTH_BYTES = 12
DEVICE_KEY_LENGTH_BYTES = 32

# APNs statuses/reasons that mean this token will never work again (app
# uninstalled, or the token was reissued by a reinstall/rebuild) — the
# caller should stop retrying and remove the device record, not just log
# a failure forever. https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
PERMANENT_FAILURE_REASONS_BY_STATUS = {
    400: {"BadDeviceToken"},
    410: {"Unregistered"},
}


class PermanentDeviceFailure(Exception):
    """APNs told us this specific token is permanently dead."""


def apns_is_configured():
    return all([APNS_KEY_PATH, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID]) and os.path.exists(
        APNS_KEY_PATH
    )


def environment_for_device(device):
    """The gateway a device's pushes must use: what it reported at
    registration, or the legacy server-wide default for older records."""
    reported_environment = device.get("apnsEnvironment")
    if reported_environment in KNOWN_APNS_ENVIRONMENTS:
        return reported_environment
    return LEGACY_DEFAULT_ENVIRONMENT


def signing_key_for_environment(environment):
    """(key_path, key_id) for an environment. Production prefers the
    dedicated production key and falls back to the main key (correct when
    that key is All-scoped; a Sandbox-scoped key will be rejected by the
    production gateway with 403 InvalidProviderToken — the error names the
    misconfiguration)."""
    if environment == PRODUCTION_ENVIRONMENT and APNS_PRODUCTION_KEY_PATH and APNS_PRODUCTION_KEY_ID:
        return APNS_PRODUCTION_KEY_PATH, APNS_PRODUCTION_KEY_ID
    return APNS_KEY_PATH, APNS_KEY_ID


def generate_device_encryption_key():
    """A fresh per-device key, handed to the device exactly once at
    registration and stored server-side for encrypting its pushes."""
    return base64.b64encode(secrets.token_bytes(DEVICE_KEY_LENGTH_BYTES)).decode()


def encrypt_notification_payload(device_encryption_key_base64, notification_title, notification_body):
    plaintext_json = json.dumps(
        {"title": notification_title, "body": notification_body}
    ).encode("utf-8")
    key_bytes = base64.b64decode(device_encryption_key_base64)
    nonce_bytes = secrets.token_bytes(AES_GCM_NONCE_LENGTH_BYTES)
    ciphertext_with_tag = AESGCM(key_bytes).encrypt(nonce_bytes, plaintext_json, None)
    return base64.b64encode(nonce_bytes + ciphertext_with_tag).decode()


def _build_provider_token(signing_key_path, signing_key_id):
    import jwt  # PyJWT; imported lazily so tests can run without APNs config

    with open(signing_key_path, "rb") as key_file:
        signing_key_pem = key_file.read()
    return jwt.encode(
        {"iss": APNS_TEAM_ID, "iat": int(time.time())},
        signing_key_pem,
        algorithm="ES256",
        headers={"kid": signing_key_id},
    )


# One cached token per signing key: the development and production keys
# differ, so a single shared cache would hand the wrong JWT to one gateway.
_cached_provider_tokens_by_key_id = {}


def get_provider_token(environment=None):
    signing_key_path, signing_key_id = signing_key_for_environment(
        environment or LEGACY_DEFAULT_ENVIRONMENT
    )
    cached_token, issued_at = _cached_provider_tokens_by_key_id.get(signing_key_id, (None, 0.0))
    if cached_token is None or time.time() - issued_at > PROVIDER_TOKEN_REFRESH_SECONDS:
        cached_token = _build_provider_token(signing_key_path, signing_key_id)
        _cached_provider_tokens_by_key_id[signing_key_id] = (cached_token, time.time())
    return cached_token


def send_encrypted_notification(device, notification_title, notification_body):
    """Sends one E2E-encrypted push to one registered device dict
    ({token, encryptionKey, ...}). Raises on failure so callers decide
    retry semantics. Returns the APNs id header for logging."""
    import httpx  # lazy: http2 extra only needed once APNs is in use

    apns_request_payload = {
        "aps": {
            # Placeholder alert: what iOS shows only if the extension fails.
            "mutable-content": 1,
            "alert": {"title": "Notification", "body": "🔒"},
            "sound": "default",
        },
        "encryptedPayload": encrypt_notification_payload(
            device["encryptionKey"], notification_title, notification_body
        ),
    }
    device_environment = environment_for_device(device)
    with httpx.Client(http2=True, timeout=10) as http_client:
        response = http_client.post(
            f"{APNS_GATEWAY_BY_ENVIRONMENT[device_environment]}/3/device/{device['token']}",
            json=apns_request_payload,
            headers={
                "authorization": f"bearer {get_provider_token(device_environment)}",
                "apns-topic": APNS_BUNDLE_ID,
                "apns-push-type": "alert",
                "apns-priority": "10",
            },
        )
    permanent_failure_reasons = PERMANENT_FAILURE_REASONS_BY_STATUS.get(response.status_code)
    if permanent_failure_reasons:
        try:
            reason = response.json().get("reason", "")
        except Exception:
            reason = ""
        if reason in permanent_failure_reasons:
            raise PermanentDeviceFailure(f"{response.status_code} {reason}")
    response.raise_for_status()
    return response.headers.get("apns-id", "")
