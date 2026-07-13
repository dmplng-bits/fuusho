"""
fuusho server — entry point.

This file only wires things together: create the Flask app, register the
API blueprint, expose a health check. All real logic lives under backend/.

Run directly:      python server.py            (dev server, port 5000)
Run in production:  gunicorn -b 0.0.0.0:5000 server:flask_app
Pair a device:       flask --app server pair
"""

import json
import os

from flask import Flask, jsonify

from backend import pairing
from backend.routes import api_blueprint

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


if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=5000)
