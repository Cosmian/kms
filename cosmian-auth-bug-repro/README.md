# Cosmian auth-server + APISIX forward-auth — bug reproduction

Standalone, self-contained reproduction of two bugs found in
`ghcr.io/cosmian/auth-server` while wiring it up behind APISIX's
`forward-auth` plugin. No Kubernetes required — everything runs via
`docker compose`.

## What this shows

1. **BUG 1** — Every admin-authenticated write endpoint
   (`POST /admins/realms`, `POST /realms/{realm}/userpass`) crashes with:
   ```
   HTTP 500
   "unexpected error: Failed to query admin by auth scheme and value:
     DB query error: no column found for name: client_certificate"
   ```
   This happens regardless of realm/username/payload — it fires before any
   request-specific logic runs, on the admin-identity resolution step.
   Root cause (confirmed against source snippets): the DB column is named
   `certificate`, but the `Admin` struct field is `client_certificate`
   with no `#[sqlx(rename = "certificate")]`, so the row→struct mapping
   fails whenever the auth-scheme fallback chain reaches the (last)
   certificate check.

2. **BUG 2** — Login for any user other than the seeded `admin` account
   fails with:
   ```
   HTTP 401
   "Authentication service error"
   ```
   on every realm, with any password, however the user was created (direct
   DB insert or the admin API in bug 1, when it isn't broken). Only the
   dev-seeded `admin` on realm `_` can ever authenticate.

3. **APISIX / `forward-auth` is not at fault.** The gateway only ever
   relays auth-server's own HTTP status code and body verbatim to the
   client — proven both by the `upstream_status` field in APISIX's access
   log and by temporarily instrumenting the `forward-auth` plugin itself
   (see "Proving APISIX is not at fault" below).

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`, not `docker-compose`)
- `curl`, `openssl`
- Internet access (to pull images, and to `apk add argon2` inside a
  throwaway Alpine container during the repro script)

## Usage

```bash
cd cosmian-auth-bug-repro
./test-scripts/setup.sh        # generates TLS/JWT keys, starts the stack
./test-scripts/reproduce.sh    # runs the full repro, prints PASS/FAIL per step
./test-scripts/teardown.sh     # stops everything, removes generated keys
```

Expected output of `reproduce.sh` (abridged):

```
== 1. Protected route without a session cookie -> expect 401 ==
  PASS GET protected/ (no cookie) -> 401

== 2. Login as the seeded admin (realm=_) -> expect 200 + session cookie ==
  PASS Admin login -> 200, cookie captured

== 3. BUG 1 -- create a realm via the admin API -> expect 500 (client_certificate) ==
  FAIL POST /admins/realms -> 500 'no column found for name: client_certificate' (BUG confirmed)

== 5. BUG 1 (again) -- create a normal user via the admin API -> expect 500 ==
  FAIL POST /realms/test-realm/userpass -> 500 'client_certificate' (BUG confirmed, same root cause as step 3)

== 7. BUG 2 -- login as a normal (non-admin) user -> expect 401 ==
  FAIL POST /login?realm=test-realm (testuser) -> 401 'Authentication service error' (BUG confirmed)

== 8. Sanity -- forward-auth mechanics work when auth-server actually succeeds ==
  PASS GET protected/ with admin cookie -> 200 (APISIX + forward-auth relay correctly)
```

`FAIL` here means "the bug reproduced as expected", not that the script
itself failed — it's testing that a bug is present, so a `FAIL` is the
expected outcome for steps 3, 5, and 7 until the underlying image is fixed.

## Stack layout

```
client -> APISIX (:9080) -> forward-auth check -> auth-server (:8443, internal)
                          -> upstream (protected-app, nginx placeholder)

auth-server -> postgres (schema auto-created) + redis (sessions)
```

Two virtual hosts are configured on the gateway:
- `auth.repro.local` — direct passthrough to auth-server (login, `/whoami`,
  admin API). No `forward-auth` here; this *is* auth-server, not a
  protected app.
- `protected.repro.local` — a dummy upstream (`nginx:alpine`) guarded by
  the `forward-auth` plugin, checking `https://auth-server:8443/whoami?realm=test-realm`.

## Proving APISIX is not at fault

The `reproduce.sh` script relies on the `upstream_status` field already
present in APISIX's access log (see `apisix-config.yaml`'s
`access_log_format`) to show that every status code the client receives
originates from auth-server, not from APISIX's own logic.

For an even more direct proof, you can temporarily patch the running
`forward-auth` plugin to log the raw response it receives from
auth-server before returning it to the client:

```bash
docker compose exec apisix sh -c \
  "cp /usr/local/apisix/apisix/plugins/forward-auth.lua /tmp/forward-auth.lua.bak"

docker compose cp apisix:/tmp/forward-auth.lua.bak /tmp/forward-auth.lua
# insert, right after `local res, err = httpc:request_uri(conf.uri, params)`:
#   core.log.warn("DEBUG status=", res.status, " body=", res.body)
docker compose cp /tmp/forward-auth.lua apisix:/usr/local/apisix/apisix/plugins/forward-auth.lua
docker compose exec apisix apisix reload

# trigger a request, then check:
docker compose logs apisix | grep DEBUG

# restore afterwards:
docker compose exec apisix sh -c \
  "cp /tmp/forward-auth.lua.bak /usr/local/apisix/apisix/plugins/forward-auth.lua"
docker compose exec apisix apisix reload
```

The logged `res.status` / `res.body` will match exactly what the client
receives — because `forward-auth.lua` does `return res.status, res.body`
verbatim, with no transformation.

## Known-good vs known-broken

| Action | Result |
|---|---|
| Login `admin` / realm `_` | 200, valid session cookie |
| `admin` cookie on any realm's `/whoami` check | 200 — admin sessions aren't realm-scoped |
| `POST /admins/realms` (any payload, any realm name) | 500, always |
| `POST /realms/{realm}/userpass` (any payload) | 500, always |
| Login any non-admin user (any realm, correct password, any creation method) | 401 "Authentication service error", always |

## Cleaning up

```bash
./test-scripts/teardown.sh
```
