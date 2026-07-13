"""
Persistence layer for fuusho server state.

A single SQLite table stores one JSON blob per named category, keyed by
name — no per-field schema, the caller and this module agree on each
category's shape by convention (see STATE_DEFAULT_VALUES_BY_NAME below).
"""

import copy
import json
import os
import sqlite3
from pathlib import Path

# Optional in-process override (tests use it); None = read the DB_PATH
# env var at call time, so embedders can set it whenever — import order
# doesn't matter.
DATABASE_FILE_PATH = None


def database_file_path():
    return DATABASE_FILE_PATH or os.environ.get("DB_PATH", "/data/fuusho.sqlite3")


STATE_CATEGORY_NAMES = {
    # Registered APNs devices — shape documented in fuusho/routes.py
    "devices",
    # In-flight QR pairing sessions, keyed by token — shape documented in
    # fuusho/pairing.py. Short-lived (~90s) and pruned lazily on access.
    "pairingSessions",
}

STATE_DEFAULT_VALUES_BY_NAME = {
    "devices": [],
    "pairingSessions": {},
}


def open_database_connection():
    Path(database_file_path()).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_file_path())
    connection.execute(
        "CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value TEXT)"
    )
    return connection


def read_state(state_name):
    connection = open_database_connection()
    result_row = connection.execute(
        "SELECT value FROM state WHERE name = ?", (state_name,)
    ).fetchone()
    connection.close()
    if result_row is None:
        # Deep copy, never the shared default itself: callers mutate what
        # they get back, and handing out the module-level default would
        # let one request's mutation bleed into every later read of a
        # still-unwritten category.
        return copy.deepcopy(STATE_DEFAULT_VALUES_BY_NAME[state_name])
    return json.loads(result_row[0])


def write_state(state_name, state_value):
    connection = open_database_connection()
    connection.execute(
        "INSERT INTO state (name, value) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (state_name, json.dumps(state_value)),
    )
    connection.commit()
    connection.close()
