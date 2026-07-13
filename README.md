# fuusho

**封書** (fūshō) — Japanese for "sealed letter." A self-hosted push
notification server: end-to-end encrypted APNs delivery, QR-bootstrapped
device pairing, and a curl-friendly HTTP API. Extracted from PrivatePush
(the iOS client, not yet published, and the first app built on this
server) so it can be run standalone by any developer who wants their own
push infrastructure instead of a third-party relay.

**What makes this different from ntfy / Gotify / Pushover:** those relay
your notification content in the clear. This server never sees plaintext
either — each device gets its own AES-256-GCM key, generated **on the
device**, during a pairing handshake that never puts the key on the wire
unencrypted (see [Security model](#security-model) below).

**[→ See how it works](docs/how-it-works.html)** — a plain-language
walkthrough plus the real architecture and pairing-sequence diagrams.
Open the file locally, or view it rendered if this repo is on GitHub
Pages.

![Setup to first pairing, in one terminal session: clone, init.py, docker compose up, scan the QR, confirm delivery](docs/demo.gif)

Every line above is real output from this repo, not a mockup — the
setup wizard's actual prompts, the actual `docker compose up` shape, and
a QR rendered from a real (if illustrative) pairing payload.

## Who this is for

- **Homelab / self-hosters** already running Uptime Kuma, Grafana, a CI
  runner, or cron jobs who want alerts on their phone without piping the
  content of those alerts through ntfy.sh, Pushover, or any other third
  party that can read them.
- **iOS developers building their own app** who want push notifications
  without building APNs plumbing, an encryption scheme, and a pairing UX
  from scratch — this server is a drop-in backend; you only write the
  `POST /api/notify` call.
- **Anyone who tried ntfy / Gotify / Pushover and hit the same wall**:
  "self-hosted" still meant plaintext in transit, Pushover's free tier
  caps out at 7,500 messages/month, or Bark's own docs call its
  encryption mode "experimental."

## What you'd actually use it for

![Sending a real push with curl, then confirming which device received it](docs/demo-notify.gif)

Concrete, not hypothetical — these are the shapes of thing a single
`POST /api/notify` call replaces:

- **CI/CD**: a GitHub Actions / GitLab CI step that pings your phone
  when a deploy finishes or a build breaks.
  ```bash
  curl -X POST $FUUSHO_URL/api/notify -d '{"title":"Deploy failed","body":"main @ a3f9c2"}'
  ```
- **Uptime/monitoring**: Uptime Kuma, Healthchecks.io, or Grafana
  Alerting configured to hit `/api/notify` as a generic webhook target
  when something goes down.
- **Long-running jobs**: a training run, a backup script, a data
  pipeline — one line at the end of the script instead of babysitting a
  terminal.
- **Home automation / security**: a motion sensor, a door lock, a NAS
  health check — anything already running on a box you own that wants
  to reach you without going through a cloud IoT platform.
- **Your own iOS app**: skip building push infrastructure from scratch
  — see [Integrating fuusho into your own app](#integrating-fuusho-into-your-own-app).

## Who this is *not* for

Being upfront about this is more useful than a feature list — if any of
these describe you, you'll be happier with something else:

- **"I don't want to run a server, ever."** That's not a fuusho
  limitation, it's the entire premise — self-hosting is the trade you're
  making for the encryption guarantee. If a managed relay is fine and
  you just want it working in two minutes, use [Pushover](https://pushover.net)
  (paid, no server) or [ntfy.sh](https://ntfy.sh) (free, hosted, no
  server, no E2E encryption).
- **You need Android delivery today.** Server and protocol are
  platform-agnostic by design (see the integration section), but the
  only channel actually wired up is APNs. If Android is a hard
  requirement right now, not this — look at ntfy or a
  UnifiedPush-based setup instead.
- **You want a dashboard, user accounts, or a team/multi-tenant
  platform.** This is one operator running one server for their own
  devices — there's no login system and it's not trying to become one.
  For actual multi-tenant notification infrastructure, look at
  something like Novu or Courier.
- **You need an SLA, support contract, or guaranteed delivery.** This is
  homelab-grade software: no on-call, no uptime guarantee, no vendor to
  escalate to. Apple's own APNs reliability is the ceiling either way.

## Why this exists

| | ntfy / Gotify | Pushover | fuusho |
|---|---|---|---|
| Self-hosted | Yes | No — SaaS only | Yes |
| End-to-end encrypted | No — server sees plaintext | No | Yes — per-device key, generated on-device |
| Pairing | Manual token/topic entry | Account + device key | QR scan, single-use, ~90s TTL |
| API | curl-friendly | curl-friendly | curl-friendly |
| Cost | Free | ~$5/platform | Free — runs on hardware you already own |

If you don't care about encryption and just want the simplest possible
self-hosted relay, ntfy is genuinely good and you should use it instead.
This project exists specifically for the case where you don't want your
own server to be able to read your notifications either — CI secrets,
health alerts, or anything else you'd rather not have sitting in
plaintext in a log somewhere.

## What's not here (yet)

Scope, stated plainly rather than discovered by hitting a wall:

- **Android/FCM delivery.** The pairing protocol doesn't care what
  platform a device is, but only `apns_client.py` exists — no
  `fcm_client.py` yet.
- **A web dashboard.** The only UI is the `/pair` page. Everything else
  is the HTTP API — no login, no device-management screen, no history
  view.
- **Multi-user or multi-tenant accounts.** One server, one operator, your
  own devices. No concept of "users" at all.
- **Message history.** Once a push is delivered, fuusho doesn't keep a
  copy — nothing to retain means nothing to leak later, but also means
  no "what did I miss" view if you want one.
- **Rich media.** Title + body, text only. No images, no attachments.
- **Delivery retries or a queue.** One APNs attempt per call; a failed
  send returns an error to *you*, and retrying is your caller's job (a
  CI step, a cron job) not the server's.
- **Built-in HTTPS.** Plain HTTP by default — put it behind your own
  reverse proxy, Tailscale, or Caddy if you want TLS. (This is also why
  the iOS client needs `NSAllowsArbitraryLoads` — see
  [Gotchas](#gotchas).)
None of these are permanently off the table — they're just not built,
and this list exists so you find that out from a README instead of a
support request.

## Getting started, step by step

### 0. What you need first

- **Docker** (Docker Desktop, or Colima/OrbStack if you're not on Docker
  Desktop). If `docker --version` doesn't work in your terminal, install
  that first — everything below assumes it's already running.
- **An APNs key from Apple** — optional to *start*, required to actually
  *deliver* a push. If you don't have one yet, keep reading; the wizard
  below lets you skip it and come back later. To get one: at
  [developer.apple.com](https://developer.apple.com) → Certificates,
  Identifiers & Profiles → Keys → "+" → check "Apple Push Notifications
  service (APNs)" → download the `.p8` file (Apple only lets you download
  it **once**, so save it somewhere safe immediately). Note the **Key
  ID** shown on that page and your **Team ID** (Membership tab).

### 1. Clone the repo

```bash
git clone <this repo>
cd fuusho
```

### 2. Run the setup wizard

```bash
python3 init.py
```

This is interactive — here's exactly what it asks and what to type:

| It asks | What to answer |
|---|---|
| `Address your phone will reach this server at` | Press Enter to accept its guessed default, or type the IP/hostname your phone can actually reach — e.g. `http://192.XXX.XXX.XXX:8090` on your home network, or a Tailscale/public hostname if this server isn't on the same LAN as your phone. |
| `Configure APNs now? [Y/n]` | `y` if you have your `.p8` file ready; `n` to skip — the server will still run and pairing will still work, you just won't get real pushes until you re-run this. |
| `Path to your AuthKey_XXXXXXXXXX.p8 file` | Drag the file into the terminal, or type/paste the full path. The wizard copies it into `./secrets/` and locks its permissions — your original copy is untouched. |
| `APNs Key ID` | The 10-character ID from the Apple Developer portal page where you created the key. |
| `Apple Team ID` | From the **Membership** tab of your Apple Developer account (also 10 characters). |
| `App bundle id` | e.g. `com.yourname.yourapp` — must match the bundle ID of the app that will receive the pushes. |
| `Is this a development build installed via Xcode?` | `y` while you're testing from Xcode; `n` once you move to TestFlight or the App Store. |
| `Generate an internal API secret?` | `y` is recommended — this is what stops a random device on your network from triggering `POST /api/notify`. It prints the generated secret at the end; save it. |

When it finishes, it's written a `.env` file (permissions locked to you
only) and, if you configured APNs, copied your key into `./secrets/`
(also locked down). Nothing here talks to the network yet.

### 3. Start the server

```bash
docker compose up -d
```

First run builds the container (a minute or so); after that, starts in
seconds. Confirm it's alive:

```bash
curl http://localhost:8090/healthz
# {"ok":true}
```

### 4. Pair your first device

```bash
docker compose exec web flask --app server pair
```

This prints a QR code right in your terminal. Scan it with the
PrivatePush iOS app (not yet published), or open
`http://<PUBLIC_SERVER_URL>/pair` in a browser for the same code as a
scannable image — it auto-refreshes every ~70 seconds so it's never
stale by the time you get your phone out. No camera handy? The same
command also prints the raw code to paste into the app's "Enter
Manually" field.

### 5. Confirm it actually works

```bash
curl -X POST http://localhost:8090/api/notify \
  -H "Content-Type: application/json" \
  -d '{"title": "It works", "body": "fuusho is up and delivering"}'
```

If you skipped APNs setup in step 2, this will report a delivery
failure — that's expected, not a bug. Re-run `python3 init.py` with your
real credentials, then try again.

If you generated an `INTERNAL_API_SECRET` in step 2, every call to
`/api/notify` needs `-H "X-Internal-Secret: <that secret>"` — including
this one.

That's the whole setup. Everything past this point is reference material.

## API reference

| Method & path | Purpose |
|---|---|
| `POST /api/pair/start` | Start a pairing session; returns the QR payload |
| `GET /pair` | Same payload, rendered as a scannable QR image (HTML page) |
| `POST /api/pair/complete` | Finish pairing (called by the client, not by hand) |
| `GET /api/devices` | List paired devices (names + token prefixes — never keys) |
| `DELETE /api/devices/<tokenPrefix>` | Revoke a device |
| `POST /api/notify` | Send an E2E-encrypted push to every paired device |
| `GET /healthz` | Liveness check |

Full request/response shapes are documented in the docstrings at the top
of `fuusho/routes.py`.

## Security model

Pairing is bootstrapped by a short-lived (~90s), single-use X25519 key
exchange — the same pattern Signal Desktop and WhatsApp Web use for
device linking:

1. The server generates an ephemeral keypair per pairing session and
   puts its **public key** in the QR — never a shared secret.
2. The client (scanning or pasting that QR) generates its own ephemeral
   keypair, derives a transport key via ECDH + HKDF, and generates the
   *actual* push-encryption key itself — locally, never received from
   the server.
3. The client encrypts `{deviceToken, deviceName, pushEncryptionKey}`
   under the transport key and POSTs it. The server derives the same
   transport key, decrypts, and stores the device.

Nothing sensitive crosses the network unencrypted in either direction. A
network attacker who never saw the QR can't complete the exchange — they
have no way to derive the transport key without one of the two private
keys, neither of which is ever transmitted. What this doesn't protect
against: someone else physically seeing or screenshotting the QR before
you scan it — same caveat as every QR-pairing flow, mitigated by the
short TTL and single-use token.

Full implementation: `fuusho/pairing.py`.

## Integrating fuusho into your own app

You don't have to use the PrivatePush iOS app. fuusho is a generic
backend — anything that speaks its pairing protocol and pushes to APNs
can be your client.

**What you get for free, no code required:**
- The server: pairing sessions, device storage, APNs delivery, the HTTP
  API.
- Sending a push from your own backend/CI/scripts — that's just
  `POST /api/notify`, no client-side crypto involved at all.

**Already running a Flask app? Embed fuusho instead of running a second
service.** The server is an installable package with the whole API on
one blueprint:

```bash
pip install "fuusho @ git+https://github.com/dmplng-bits/fuusho"
```

```python
from fuusho import api_blueprint, dispatch_notification

your_flask_app.register_blueprint(api_blueprint)   # /pair, /api/devices, /api/notify …
dispatch_notification("Backup finished", "42 GB")  # push without the HTTP hop
```

Configuration stays the same environment variables either way (see
[Configuration](#configuration)) — they're read lazily, so set them
anywhere before the first request; import order doesn't matter. Running
standalone instead is `gunicorn "fuusho:create_app()"` (that's all the
Docker image does).

**What you have to build:** the pairing handshake on your client, since
that's what generates the device's own encryption key. Today the only
reference implementation is Swift (`PairingCrypto.swift` in the
PrivatePush app). Porting it to Kotlin, JavaScript, or anything else
means implementing this exact sequence — every step below uses
standard, widely-available crypto primitives, nothing custom:

1. Scan or receive the QR payload — plain JSON:
   ```json
   { "v": 1, "server": "http://...", "token": "...", "pub": "<base64 X25519 public key>" }
   ```
2. Generate your own ephemeral **X25519** keypair.
3. Compute the ECDH shared secret with the server's public key (`pub`).
4. Derive a 32-byte transport key: **HKDF-SHA256**, `salt = token`
   (UTF-8 bytes), `info = "privatepush-pairing-v1"` (yes, that string —
   it's a protocol constant, unrelated to the server's current name).
5. Generate a fresh 32-byte **AES-256** key locally — this becomes the
   device's actual push-decryption key. It never gets sent anywhere
   except encrypted in the next step.
6. Encrypt `{"apnsDeviceTokenHex": "...", "deviceName": "...", "pushEncryptionKey": "<base64>", "apnsEnvironment": "development" | "production"}`
   with **AES-256-GCM** under the transport key. `apnsEnvironment` is
   optional but recommended: report `development` for Xcode/simulator
   installs and `production` for TestFlight/App Store installs, and the
   server routes your pushes through the matching APNs gateway. Omit it
   and the server falls back to its `APNS_USE_SANDBOX` default.
7. POST to `{server}/api/pair/complete`:
   ```json
   { "token": "...", "appPublicKey": "<base64>", "nonce": "<base64, 12 bytes>", "ciphertext": "<base64, ciphertext+tag>" }
   ```
8. On success, store the key from step 5 in your platform's secure
   storage (Keychain, Keystore, etc.) — that's what decrypts every push
   from here on.

**Receiving and decrypting a push:** APNs delivers `{"aps": {...},
"encryptedPayload": "<base64>"}`. Split the base64-decoded blob into a
12-byte nonce and the remaining ciphertext+tag, then AES-256-GCM-decrypt
with the key from step 5 to get `{"title": "...", "body": "..."}`.

**Honest gap:** only APNs (iOS) delivery exists server-side today —
`apns_client.py` is APNs-specific. Android/FCM support would mean adding
a parallel `fcm_client.py` and a device-type field; nobody's needed it
yet, but the pairing protocol above doesn't care what platform the
device is, so it's additive, not a redesign.

## Configuration

Everything is env vars (see `.env.example`), written for you by
`init.py`:

| Variable | Purpose |
|---|---|
| `PUBLIC_SERVER_URL` | Address the pairing QR points clients at |
| `APNS_KEY_PATH` / `APNS_KEY_ID` / `APNS_TEAM_ID` / `APNS_BUNDLE_ID` | APNs credentials |
| `APNS_USE_SANDBOX` | Legacy fallback only — devices report their own environment at pairing and are routed per-device; this covers records that predate that. `true` = development gateway, `false` = production |
| `APNS_PRODUCTION_KEY_PATH` / `APNS_PRODUCTION_KEY_ID` | Optional second signing key for the production gateway — required if the main key is Sandbox-scoped, unnecessary if it's All-scoped |
| `INTERNAL_API_SECRET` | Optional — gates `POST /api/notify` |
| `DB_PATH` | SQLite file path (default `/data/fuusho.sqlite3`, already volume-mounted) |

## Deploying

**Docker (any host):** the quickstart above works anywhere Docker runs —
a homelab box, a Raspberry Pi, a VPS.

**Cloud (Fly.io / Render):** `fly.toml` and `render.yaml` are included —
each has its exact setup steps in its own comments. Both give you HTTPS
for free, which also removes the `NSAllowsArbitraryLoads` gotcha on the
iOS side entirely. Two constraints to respect:

- **One instance only.** State is a SQLite file on the attached volume —
  scaling horizontally would split your device registry. For a personal
  push server, one tiny instance is genuinely all it needs.
- **The `.p8` key can't be bind-mounted** like in docker-compose; both
  configs ship it as a secret (`APNS_KEY_PEM` = the file's contents)
  that's written to disk at boot.

**The honest trade-off of leaving your LAN:** pushes are encrypted
per-device *on the server*, so the machine running fuusho briefly
handles plaintext and permanently holds the device keys and your APNs
signing key. Self-hosted at home, that machine is yours; on a cloud VM,
you're trusting the provider's infrastructure with it. Still far better
than a third-party relay reading every message as a product feature —
but it's a real boundary shift, so it's your call, not fine print.

## Running the tests

```bash
pip install -r app/requirements.txt pytest
python -m pytest tests/ -q
```

35 tests cover the pairing handshake (including that a forged public key
can't complete someone else's session), the per-device delivery fan-out,
per-device APNs environment routing, and every HTTP route.

## Gotchas

Real things that tripped this project up, kept here so they don't trip
you up too:

- **Pairing sessions live in SQLite, not a Python dict, on purpose.**
  The container runs 3 gunicorn workers with no shared memory — a
  module-level dict would make pairing fail whenever the QR-issuing
  request and the registration request land on different workers. If
  you're extending `pairing.py`, keep using `state_store`.
- **The Dockerfile needs BuildKit.** The `--mount=type=cache` /
  `--mount=type=bind` lines fail with *"the --mount option requires
  BuildKit"* on a plain legacy builder. Docker Desktop has this on by
  default; if you're on a minimal Docker install (no Desktop, e.g.
  Colima), you also need the `buildx` **and** `compose` CLI plugins —
  neither ships with the bare `docker` binary. (This is exactly how this
  repo's own setup was verified — no Docker Desktop, no Homebrew, no
  sudo: `colima` for the daemon, `docker-buildx` and `docker-compose`
  dropped straight into `~/.docker/cli-plugins/` from their GitHub
  releases.)
- **The container runs as root.** Non-root is the more correct default,
  but the `.p8` key file is bind-mounted from the host and currently
  chmod'd `400` (owner-only) by `init.py` — a non-root container user
  almost certainly has a different UID than your host user and would
  fail to read it. Fixing this means loosening that permission *and*
  testing it against a real daemon; not done here.
- **APNs sandbox vs. production is per-device, and your signing key has
  a scope.** Devices installed via Xcode get sandbox APNs tokens;
  TestFlight and App Store installs get production tokens. A push sent
  to the wrong gateway fails with `BadDeviceToken`, which is why the
  server routes each device by the `apnsEnvironment` it reported at
  pairing (devices that never reported one use the `APNS_USE_SANDBOX`
  fallback). The part that still bites: Apple scopes `.p8` keys — a
  **Sandbox-scoped key cannot sign for the production gateway** (403
  `InvalidProviderToken`). If yours is Sandbox-scoped, create a
  Production or All-scoped key in the portal and set
  `APNS_PRODUCTION_KEY_PATH` / `APNS_PRODUCTION_KEY_ID`; if it's
  All-scoped, one key serves both gateways and you set nothing extra.
- **Apple gives you exactly one download of the `.p8` key.** Lose it
  and you revoke + regenerate + update `APNS_KEY_ID` everywhere it's
  referenced. Back it up somewhere the moment you download it.
- **A raw-IP `PUBLIC_SERVER_URL` needs `NSAllowsArbitraryLoads` on iOS,
  not the narrower `NSAllowsLocalNetworking`.** The scoped exception
  only covers `.local`/unqualified hostnames — iOS has no equivalent
  scoped exception for a bare IP address, which is what most people's
  server address actually is on first setup. Prefer HTTPS or a real
  hostname once you have one.
- **Port 5000 is often already taken on a Mac** (macOS's AirPlay
  Receiver / Control Center claims it) — irrelevant if you're only ever
  hitting the Docker port mapping (`8090` by default), but it'll bite
  you if you ever run `python server.py` directly on a Mac for local
  debugging.
- **A saved/printed QR code goes stale.** The pairing token expires in
  ~90s and is single-use. The live `/pair` page auto-refreshes so this
  is invisible there, but a screenshot of it won't be valid by the time
  you actually scan it.

## License

MIT — see `LICENSE`.
