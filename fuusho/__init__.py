"""
fuusho — self-hosted, end-to-end-encrypted push notifications for your
own app. Importable as a library or run standalone (see create_app).

  state_store.py           -- persistence layer (SQLite, one row per category)
  pairing.py                -- QR-bootstrapped X25519 device pairing
  apns_client.py              -- direct APNs sender, E2E-encrypted payloads
  notification_dispatch.py      -- delivery choke point, used by routes.py
  routes.py                       -- the entire HTTP API

Two ways to use it:

  Standalone service (what docker-compose runs):
      gunicorn "fuusho:create_app()"

  Embedded in your own Flask app:
      from fuusho import api_blueprint
      your_flask_app.register_blueprint(api_blueprint)

  Sending a push from your own code (no HTTP hop needed when embedded):
      from fuusho import dispatch_notification
      dispatch_notification("Backup finished", "42 GB in 12 min")

All configuration is environment variables (APNS_*, DB_PATH,
PUBLIC_SERVER_URL, INTERNAL_API_SECRET) — read lazily, so setting them
before first use is enough; import order doesn't matter.
"""

import json
import os

from flask import Flask, jsonify

from .notification_dispatch import dispatch_notification
from .routes import api_blueprint

__all__ = ["api_blueprint", "create_app", "dispatch_notification"]


def create_app():
    """Application factory for running fuusho as its own service.

    Adds the index + health endpoints and the `flask pair` CLI command on
    top of the blueprint. Embedders who already have a Flask app should
    register `api_blueprint` on it instead of calling this.
    """
    from . import pairing

    flask_app = Flask(__name__)
    flask_app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # 1MB cap on request bodies
    flask_app.register_blueprint(api_blueprint)

    @flask_app.get("/")
    def index():
        return jsonify({
            "service": "fuusho",
            "ok": True,
            "pair": "/pair",
        })

    @flask_app.get("/healthz")
    def health_check():
        return {"ok": True}

    @flask_app.cli.command("pair")
    def pair_command():
        """Print a QR (plus the raw payload, for pasting) to pair a new
        device without opening a browser.

        Usage: docker compose exec web flask --app server pair
        """
        public_server_url = os.environ.get("PUBLIC_SERVER_URL", "http://localhost:8090")
        session = pairing.create_pairing_session(public_server_url)
        payload_json = json.dumps(session)
        pairing.print_ascii_qr(payload_json)
        print(f"\nOr open {public_server_url}/pair in a browser (it auto-refreshes).")
        print(f"No camera? Paste this into \"Enter Manually\":\n{payload_json}")
        print(f"\nExpires in {pairing.PAIRING_SESSION_TTL_SECONDS}s if unscanned.")

    return flask_app
