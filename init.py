#!/usr/bin/env python3
"""
Interactive setup wizard for fuusho.

Writes a .env file (read by docker-compose.yml) and copies your APNs .p8
key into ./secrets/ with the right permissions. This is the one part of
setup that can't be automated away — Apple requires every developer to
generate their own APNs key from their own account, so this script's job
is to make that a two-minute copy/paste instead of a hand-edited .env.

Usage:
    python3 init.py
"""

import re
import secrets
import shutil
import socket
import stat
from pathlib import Path

REPO_ROOT = Path(__file__).parent
ENV_FILE_PATH = REPO_ROOT / ".env"
SECRETS_DIRECTORY_PATH = REPO_ROOT / "secrets"

APNS_KEY_ID_PATTERN = re.compile(r"^[A-Z0-9]{10}$")
APNS_TEAM_ID_PATTERN = re.compile(r"^[A-Z0-9]{10}$")
BUNDLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9.\-]+$")


def prompt(question, default=None):
    suffix = f" [{default}]" if default else ""
    answer = input(f"{question}{suffix}: ").strip()
    return answer or default or ""


def prompt_yes_no(question, default_yes=True):
    suffix = " [Y/n]" if default_yes else " [y/N]"
    answer = input(f"{question}{suffix}: ").strip().lower()
    if not answer:
        return default_yes
    return answer.startswith("y")


def guess_lan_ip():
    """Best-effort LAN IP guess, purely to pre-fill a default — never
    trusted for anything security-relevant."""
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe_socket.connect(("8.8.8.8", 80))
        return probe_socket.getsockname()[0]
    except OSError:
        return "localhost"
    finally:
        probe_socket.close()


def collect_apns_config():
    print("\n--- APNs (push notifications) ---")
    print("From developer.apple.com -> Certificates, Identifiers & Profiles -> Keys.")
    print("Skip this and the server will still run — pairing works, but no pushes")
    print("will actually be sent until you come back and re-run this.\n")

    if not prompt_yes_no("Configure APNs now?", default_yes=True):
        return {"APNS_KEY_PATH": "", "APNS_KEY_ID": "", "APNS_TEAM_ID": "", "APNS_BUNDLE_ID": "", "APNS_USE_SANDBOX": "true"}

    while True:
        key_file_path = Path(prompt("Path to your AuthKey_XXXXXXXXXX.p8 file")).expanduser()
        if key_file_path.is_file():
            break
        print(f"  Can't find {key_file_path} — try again.")

    SECRETS_DIRECTORY_PATH.mkdir(mode=0o700, exist_ok=True)
    destination_path = SECRETS_DIRECTORY_PATH / key_file_path.name
    shutil.copy(key_file_path, destination_path)
    destination_path.chmod(stat.S_IRUSR)  # 400 — owner read-only
    print(f"  Copied to {destination_path} (chmod 400).")

    key_id = prompt_until_valid("APNs Key ID (10 characters, from the portal)", APNS_KEY_ID_PATTERN)
    team_id = prompt_until_valid("Apple Team ID (10 characters, Membership page)", APNS_TEAM_ID_PATTERN)
    bundle_id = prompt_until_valid("App bundle id (e.g. com.yourname.yourapp)", BUNDLE_ID_PATTERN)
    # Devices paired by a current app report their own environment and are
    # routed per-device; this only sets the fallback for older records.
    use_sandbox = prompt_yes_no("Default APNs environment for legacy devices — development (Xcode installs)? (n = production)", default_yes=True)

    return {
        "APNS_KEY_PATH": f"/secrets/{destination_path.name}",
        "APNS_KEY_ID": key_id,
        "APNS_TEAM_ID": team_id,
        "APNS_BUNDLE_ID": bundle_id,
        "APNS_USE_SANDBOX": "true" if use_sandbox else "false",
    }


def prompt_until_valid(question, pattern):
    while True:
        value = input(f"{question}: ").strip()
        if pattern.match(value):
            return value
        print(f"  That doesn't look right — expected to match {pattern.pattern}")


def write_env_file(values):
    lines = [f"{key}={value}" for key, value in values.items()]
    ENV_FILE_PATH.write_text("\n".join(lines) + "\n")
    ENV_FILE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600


def main():
    print("fuusho setup\n")

    if ENV_FILE_PATH.exists():
        if not prompt_yes_no(f"{ENV_FILE_PATH} already exists — overwrite?", default_yes=False):
            print("Left existing .env untouched. Edit it by hand or delete it and re-run.")
            return

    guessed_ip = guess_lan_ip()
    public_server_url = prompt(
        "Address your phone will reach this server at",
        default=f"http://{guessed_ip}:8090",
    )

    apns_values = collect_apns_config()

    internal_api_secret = ""
    if prompt_yes_no(
        "\nGenerate an internal API secret (recommended — gates POST /api/notify)?",
        default_yes=True,
    ):
        internal_api_secret = secrets.token_urlsafe(24)

    values = {
        "PUBLIC_SERVER_URL": public_server_url,
        **apns_values,
        "INTERNAL_API_SECRET": internal_api_secret,
    }
    write_env_file(values)

    print(f"\nWrote {ENV_FILE_PATH}.")
    print("\nNext steps:")
    print("  docker compose up -d")
    print("  docker compose exec web flask --app server pair")
    if internal_api_secret:
        print(f"\nYour INTERNAL_API_SECRET (save this for your own scripts/CI): {internal_api_secret}")


if __name__ == "__main__":
    main()
