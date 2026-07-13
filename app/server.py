"""
fuusho standalone entry point.

The real application lives in the `fuusho` package (installable, also
embeddable in your own Flask app — see fuusho/__init__.py). This file
exists so the Docker image and the docs have one obvious thing to run.

Run directly:      python server.py            (dev server, port 5000)
Run in production:  gunicorn -b 0.0.0.0:5000 server:flask_app
Pair a device:       flask --app server pair
"""

from fuusho import create_app

flask_app = create_app()

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=5000)
