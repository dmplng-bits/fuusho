"""
fuusho server backend package.

  state_store.py           -- persistence layer (SQLite, one row per category)
  pairing.py                -- QR-bootstrapped X25519 device pairing
  apns_client.py              -- direct APNs sender, E2E-encrypted payloads
  notification_dispatch.py      -- delivery choke point, used by routes.py
  routes.py                       -- the entire HTTP API

server.py (one directory up) is the composition root.
"""
