# Manual Test Plan — OIDC / Session Authentication Rework (KMS Web UI)

**Target change:** `feat/auth-server-integration` branch, in particular commit
`8ef543a2` ("IdToken to session rework first draft") plus the commits leading up
to it (`6bd4facb`, `fbafaf2b`, `f21ac1ff`, `77aefc34`).

**What changed (BFF OIDC pattern):**

- The OIDC discovery document and JWKS are now fetched **once at server startup**
  (`build_oidc_runtime_config`) and cached in `OidcRuntimeConfig` for the life of
  the process — **no per-login discovery/JWKS fetch** anymore.
- After the `/ui/callback` exchange, only `user_id` (the `email` claim) is stored
  in the server-side session cookie. **The `id_token` is never sent to the
  browser.**
- New `SessionAuth` middleware (always active) reads the session cookie on every
  request and authenticates the request server-side.
- `GET /ui/token` was **renamed to `GET /ui/whoami`** and now returns only
  `{ "user_id": "..." }` (no token).
- The UI no longer holds an `idToken` in `AuthContext`/React state, and no longer
  sends an `Authorization: Bearer <token>` header on any API call
  (`sendKmipRequest`, `getNoTTLVRequest`, `postNoTTLVRequest`,
  `getNoTTLVRequestWithTimeout` all dropped the `idToken` parameter). Every
  request instead relies on the `credentials: "include"` session cookie.

The goal of this test plan is to confirm the login/logout/session flow still
works end-to-end from a real IdP (Auth0), and — most importantly — that **no
token is ever exposed to the browser** (the whole point of the rework).

Out of scope for this pass: CERT-based auth fallback and the Cosmian
auth-server login flow (only note if you observe a regression there).

---

## 1. One-time setup

### 1.1 Auth0 application

You can either reuse the existing demo tenant referenced in
[test_data/configs/server/test/auth_ui.toml](../test_data/configs/server/test/auth_ui.toml)
(`demo-kms.eu.auth0.com`, client id `rGRvFjjLDBro8gRwxghKuiu207wKfKyG`) if you
have the corresponding client secret, or create your own Auth0 application:

1. Auth0 dashboard → **Applications** → **Create Application** → **Regular Web
   Application**.
2. Under **Settings**:
   - **Allowed Callback URLs**: `http://127.0.0.1:9998/ui/callback`
   - **Allowed Logout URLs**: `http://127.0.0.1:9998/ui/login`
   - **Allowed Web Origins**: `http://127.0.0.1:9998`
3. Note down: **Domain** (issuer, e.g. `https://acme.eu.auth0.com/`),
   **Client ID**, **Client Secret**.
4. Make sure at least one user in the tenant has a verified `email` — the
   server rejects the callback if the `email` claim is missing from the
   `id_token`.

Adjust the URLs above if you run the server on a different host/port — they
must exactly match `KMS_PUBLIC_URL` below.

### 1.2 Build the UI

```bash
cd ui
pnpm install
pnpm run build      # builds WASM + Vite production bundle into ui/dist/
```

### 1.3 Build and start the KMS server

From the repo root, on the branch under test:

```bash
git checkout feat/auth-server-integration   # or your working branch with the change
cargo build --features non-fips --bin cosmian_kms
```

Start it with the Auth0 values from 1.1:

```bash
KMS_PUBLIC_URL=http://127.0.0.1:9998 \
UI_OIDC_CLIENT_ID=<your-client-id> \
UI_OIDC_CLIENT_SECRET=<your-client-secret> \
UI_OIDC_ISSUER_URL=https://<your-tenant>.<region>.auth0.com/ \
UI_OIDC_LOGOUT_URL=https://<your-tenant>.<region>.auth0.com/v2/logout \
KMS_SESSION_SALT=$(openssl rand -hex 32) \
cargo run --features non-fips --bin cosmian_kms -- \
    --database-type sqlite --sqlite-path /tmp/kms-oidc-test \
    --ui-index-html-folder ui/dist
```

> Alternatively, copy
> [test_data/configs/server/test/auth_ui.toml](../test_data/configs/server/test/auth_ui.toml)
> to e.g. `/tmp/auth_ui_manual.toml`, add `kms_public_url` under `[http]`... (top
> level) and `ui_session_salt` under `[ui_config]`, fill in your client
> secret, then run:
> `cargo run --features non-fips --bin cosmian_kms -- --config-file /tmp/auth_ui_manual.toml`

Watch the server startup logs for:

```
OIDC: discovered endpoints from https://.../.well-known/openid-configuration
OIDC: authorization_endpoint=...
OIDC: token_endpoint=...
OIDC: jwks_uri=...
```

If instead you see `OIDC: failed to fetch/parse discovery document...`, fix the
issuer URL/network access before continuing (login will return HTTP 500 "OIDC
is not configured or discovery failed at startup").

Open `http://127.0.0.1:9998/ui/` in a fresh browser profile / incognito window
(recommended, to start with a clean cookie jar).

---

## 2. Test cases

For each test case, tick the box and note any deviation from the expected
result.

### TC1 — Happy path login

1. Navigate to `http://127.0.0.1:9998/ui/`. You should land on the login page.
2. Click the login button. You should be redirected to the Auth0 hosted login
   page.
3. Log in with a valid user (one with an `email` claim).
4. Expected: redirected back to `http://127.0.0.1:9998/ui/#/...` (or the app's
   landing route), authenticated, sidebar/menu visible, username shown.

- [ ] Pass

### TC2 — No token ever reaches the browser (critical / security)

With DevTools open (Network + Application tabs) during and after TC1:

1. **Network tab** → inspect the `/ui/callback` response: it should be a 302
   redirect with **no token in the response body or in the `Location` URL**.
2. Inspect the `/ui/whoami` request/response: response body must be exactly
   `{ "user_id": "<email>" }` — **no `id_token` field**.
3. Inspect any subsequent API call (`/version`, `/kmip/2_1`, `/access/create`,
   etc.): the request headers must have **no `Authorization` header**, only the
   `Cookie` header (session cookie) via `credentials: include`.
4. **Application tab** → Local Storage, Session Storage, IndexedDB, and all
   cookies: confirm **no `id_token`, JWT, or bearer token is stored anywhere**
   client-side. Only the actix session cookie (default name e.g. `id`) should
   be present.
5. Confirm the session cookie has `HttpOnly` set (should not be readable via
   `document.cookie` in the DevTools console).

- [ ] Pass

### TC3 — Old `/ui/token` endpoint is gone

```bash
curl -i http://127.0.0.1:9998/ui/token
```

Expected: `404 Not Found` (route no longer registered — replaced by
`/ui/whoami`).

```bash
curl -i http://127.0.0.1:9998/ui/whoami --cookie "<your-session-cookie>"
```

Expected: `200 OK` with `{"user_id": "..."}` when a valid session cookie is
passed, `401 Unauthorized` with `{"error":"No active session"}` when none is
passed.

- [ ] Pass

### TC4 — Authenticated API calls work without a bearer token

While logged in from TC1, exercise a few UI actions that hit the backend
(e.g. **Locate**, create a symmetric key, view Server Info in the header). All
should succeed. This confirms `SessionAuth` middleware correctly authenticates
KMIP/API routes purely from the session cookie, with no `Authorization` header
sent by the client (cross-check with TC2 step 3).

- [ ] Pass

### TC5 — Session persists across page reload

1. While logged in, hard-refresh the page (Ctrl+Shift+R).
2. Expected: still authenticated, no redirect to the login page, `/ui/whoami`
   succeeds again on load.

- [ ] Pass

### TC6 — Logout flow

1. Click **Logout**.
2. Expected: redirected to the Auth0 logout page, then back to
   `http://127.0.0.1:9998/ui/login` (or wherever `UI_OIDC_LOGOUT_URL`'s
   `returnTo`/redirect points).
3. Confirm the session cookie is cleared (Application tab) or now invalid.
4. Try to access `http://127.0.0.1:9998/ui/#/locate` directly (or call
   `curl http://127.0.0.1:9998/ui/whoami` reusing the old cookie value):
   expected `401`/redirect to login — access is denied.

- [ ] Pass

### TC7 — CSRF `state` mismatch is rejected

1. Start a login flow, but **before** completing it in Auth0, copy the
   `login_flow` redirect URL's `state` param aside.
2. After Auth0 redirects back to `/ui/callback?code=...&state=...`, manually
   edit the `state` query parameter in the browser address bar to a different
   value and press Enter.
3. Expected: `400 Bad Request` — `"CSRF token mismatch"`.

- [ ] Pass

### TC8 — Replaying a callback URL / stale PKCE session fails

1. Complete a successful login (TC1).
2. Copy the exact `/ui/callback?code=...&state=...` URL used.
3. Open a **new incognito window** (fresh session, no `pkce_verifier` /
   `csrf_token` / `nonce` in session) and paste that same callback URL.
4. Expected: `400 Bad Request` — `"Missing PKCE verifier"` (or CSRF/nonce
   equivalent) since the new session never went through `/ui/login_flow`.

- [ ] Pass

### TC9 — Missing/invalid OIDC client configuration

Stop the server, restart it with a wrong `UI_OIDC_ISSUER_URL` (typo'd domain)
or without `UI_OIDC_CLIENT_ID` set, and try to log in.

Expected:
- Startup log shows `OIDC: failed to fetch discovery document...` (bad
  issuer) — and `/ui/login_flow` returns `500` `"OIDC is not configured or
  discovery failed at startup"`.
- Missing client id → `500` `"Client ID is missing"`.

- [ ] Pass

### TC10 — Discovery/JWKS is cached at startup (restart required)

1. With the server running and a successful login already validated, rotate
   or otherwise change something at the IdP that would affect discovery
   (or simply note the logged `jwks_uri`/`token_endpoint` at startup).
2. Confirm the running server does **not** re-fetch discovery per login (no
   `OIDC: discovered endpoints...` log line reappears on subsequent
   `/ui/login_flow` calls — only once at startup).
3. Restart the server: confirm the discovery log line appears again exactly
   once.

- [ ] Pass

### TC11 — Session salt / restart persistence

1. Stop the server, restart it **with the same `KMS_SESSION_SALT` value** as
   before, without logging out first.
2. Reload the UI page (still holding the old session cookie).
3. Expected: **still authenticated** (session key is deterministically
   derived from `KMS_PUBLIC_URL` + salt, so the cookie remains valid across
   restarts).
4. Now restart the server **without** `KMS_SESSION_SALT` set at all (or with a
   different value) and reload.
5. Expected: session is now invalid — user is redirected to the login page.

- [ ] Pass

### TC12 — Missing `email` claim is rejected gracefully

If you can configure an Auth0 user/rule (or a test app) that omits the `email`
claim from the `id_token` (e.g. remove the `email` scope grant), attempt login.

Expected: `500 Internal Server Error` — `"Missing email claim in id_token"`,
not a silent success with an empty/undefined user.

- [ ] Pass

---

## 3. Quick checklist summary

| # | Test | Result |
|---|------|--------|
| TC1 | Happy path login | ☐ |
| TC2 | No token reaches the browser (critical) | ☐ |
| TC3 | `/ui/token` gone, `/ui/whoami` works | ☐ |
| TC4 | Authenticated API calls work (no bearer header) | ☐ |
| TC5 | Session persists across reload | ☐ |
| TC6 | Logout clears session + redirects to IdP logout | ☐ |
| TC7 | CSRF state mismatch rejected | ☐ |
| TC8 | Stale/replayed callback rejected | ☐ |
| TC9 | Bad OIDC config handled with clear error | ☐ |
| TC10 | Discovery cached at startup, refreshed only on restart | ☐ |
| TC11 | Session salt controls restart persistence | ☐ |
| TC12 | Missing email claim rejected | ☐ |

Report any failing case with: server log excerpt, browser console/network
screenshot, and the exact steps taken.
