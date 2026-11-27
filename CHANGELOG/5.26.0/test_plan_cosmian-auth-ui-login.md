# Manual Test Plan — Cosmian Authentication Server Web UI Login

**Target change:** `feat_cosmian-auth-ui-login` — adds `POST /ui/login_as` so the
KMS Web UI can authenticate end users against the proprietary Cosmian
authentication server ("AS" / "SA"), following the same BFF (Backend-For-Frontend)
session-cookie pattern as the existing OIDC flow (see
`test_plan_oidc-session-auth.md`) and functionally mirroring `ckms login cosmian`.

**What changed:**

- New `POST /ui/login_as` route: the browser posts `{ username, password,
  totp_code? }`; the KMS server replays it as HTTP Basic auth against
  `{cosmian_auth_server_url}/login?realm={realm}` (the same request `ckms login
  cosmian` makes), validates the JWT the AS returns via `Set-Cookie: _ea_=<jwt>`
  against the JWKS, and stores only the resulting `sub` (username) in the actix
  session. **The AS's JWT never reaches the browser.**
- `GET /ui/auth_method` returns `"COSMIAN"` when both `cosmian_auth_server_url`
  and the new `cosmian_auth_realm` are configured.
- The Web UI's `LoginPage` shows a username/password form (switching to a
  one-time-code prompt when the AS reports `"TotpRequired"`) for this auth
  method; `MainLayout`'s header shows the session user + a Logout button, same
  as the OIDC/JWT flow.
- `ckms login cosmian` itself is unchanged — this feature only adds the
  equivalent capability to the Web UI.

Out of scope for this pass: TOTP *enrollment*/QR-code UI, realm switcher UI, and
any admin/session-management UI for the AS — this is strictly end-user login
parity with `ckms login cosmian`.

There is no mock/wiremock harness for a live external Cosmian authentication
server in this repo, hence this manual test plan (same reasoning as the OIDC
test plan).

---

## 1. One-time setup

### 1.1 Start a local Cosmian authentication server

From the sibling `authentication` repo (workspace root — adjust the relative
path if your checkout differs):

```bash
cd authentication
cargo run -p auth_server -- server/auth_server.dev.toml
```

This starts the AS on `https://localhost:8443` with a self-signed dev
certificate, an in-memory SQLite DB, and a default admin realm (`"_"`)
containing a super-admin account: username `admin`, password `change_me`.

To exercise the TOTP test case (TC3), uncomment `admin_totp_secret` in
`server/auth_server.dev.toml` before starting the server and generate the
current code with, e.g.:

```bash
python3 -c "import pyotp; print(pyotp.TOTP('<the secret you set>').now())"
```

See `authentication/server/documentation/two_factor_authentication.md` for the
full TOTP enrollment flow if you'd rather test against a freshly-enrolled user.

### 1.2 Build the UI

```bash
cd kms/ui
pnpm install
pnpm run build      # builds WASM + Vite production bundle into ui/dist/
```

### 1.3 Build and start the KMS server

From the `kms` repo root, on the branch under test:

```bash
cargo build --features non-fips --bin cosmian_kms
```

Use the bundled test config
[test_data/configs/server/test/auth_cosmian.toml](../test_data/configs/server/test/auth_cosmian.toml)
(already points at `https://localhost:8443`, realm `"_"`, and accepts the AS's
self-signed dev certificate):

```bash
COSMIAN_KMS_CONF=test_data/configs/server/test/auth_cosmian.toml \
    cargo run --features non-fips --bin cosmian_kms
```

Watch the startup logs for the `cosmian_auth` section of the printed config
(confirms `cosmian_auth_server_url`/`cosmian_auth_realm` were loaded) and for
any `Fetch JWKS` warnings — these are non-fatal (JWKS refreshes on next login
attempt) but should stop appearing once the AS above is up.

Open `http://localhost:9998/ui/` in a fresh browser profile / incognito window
(recommended, to start with a clean cookie jar).

---

## 2. Test cases

### TC1 — Happy path login (no TOTP)

1. Navigate to `http://localhost:9998/ui/`. You should land on the login page
   with **Username** / **Password** fields (not the OIDC redirect button or
   the CERT "ACCESS KMS" button).
2. Enter `admin` / `change_me` and submit.
3. Expected: the page navigates to `/ui/locate`, authenticated, sidebar/menu
   visible, the header shows a purple tag with `admin` and a **Logout**
   button.

- [ ] Pass

### TC2 — No token ever reaches the browser (critical / security)

With DevTools open (Network + Application tabs) during and after TC1:

1. **Network tab** → inspect the `POST /ui/login_as` response body: it must be
   exactly `{"next_step":"Authenticated"}` — **no JWT / `_ea_` value anywhere
   in the response**.
2. Inspect the `/ui/whoami` request/response: response body must be exactly
   `{"user_id":"admin"}`.
3. Inspect any subsequent API call (`/version`, `/kmip/2_1`, etc.): request
   headers must have **no `Authorization` header**, only the `Cookie` header
   (session cookie) via `credentials: include`.
4. **Application tab** → Local Storage, Session Storage, IndexedDB, and all
   cookies: confirm **no `_ea_` cookie, JWT, or bearer token is stored**. Only
   the actix session cookie (`auth_session`) should be present, with
   `HttpOnly` set.

- [ ] Pass

### TC3 — TOTP-protected account

Using an account with TOTP enabled (see 1.1):

1. Submit username/password. Expected: the form switches to a single
   **one-time code** field (button label changes to **VERIFY CODE**), no
   error shown.
2. Enter the current TOTP code and submit.
3. Expected: same happy-path result as TC1.
4. Repeat with a **stale/incorrect** code: expected an inline error
   ("Authentication failed" alert) and the code field remains for retry.

- [ ] Pass

### TC4 — Bad credentials are rejected

1. Submit an invalid username or password.
2. Expected: inline "Authentication failed" alert, the form remains, no
   navigation occurs, and no session cookie is set (check Application tab).

- [ ] Pass

### TC5 — `ChangePassword` next_step surfaces an actionable error

Using an account the AS reports as requiring a password change:

1. Submit valid credentials for that account.
2. Expected: `403` from `/ui/login_as`, inline alert stating the password has
   expired and must be changed via the Cosmian authentication server — no
   silent failure, no navigation.

- [ ] Pass

### TC6 — Authenticated API calls work end-to-end

While logged in from TC1, exercise a few UI actions that hit the backend
(e.g. **Locate**, create a symmetric key, view Server Info in the header). All
should succeed, confirming `SessionAuth` authenticates KMIP/API routes from the
session cookie regardless of it having been established via the Cosmian auth
server rather than OIDC.

- [ ] Pass

### TC7 — Session persists across page reload

1. While logged in, hard-refresh the page (Ctrl+Shift+R).
2. Expected: still authenticated, no redirect to the login page, `/ui/whoami`
   succeeds again on load, `/ui/auth_method` still reports `"COSMIAN"`.

- [ ] Pass

### TC8 — Logout flow

1. Click **Logout**.
2. Expected: redirected to `http://localhost:9998/ui/login` (no external IdP
   hop — the Cosmian auth server has no logout redirect, unlike OIDC).
3. Confirm the session cookie is cleared (Application tab) or now invalid.
4. Try `curl http://localhost:9998/ui/whoami` reusing the old cookie value:
   expected `401 Unauthorized`, `{"error":"No active session"}`.

- [ ] Pass

### TC9 — `auth_method` correctly reports `COSMIAN`

```bash
curl -s http://localhost:9998/ui/auth_method
```

Expected: `{"auth_method":"COSMIAN"}`.

- [ ] Pass

### TC10 — Realm not configured falls back gracefully

Restart the server with `cosmian_auth_realm` removed/commented out from the
config (leave `cosmian_auth_server_url` set).

1. `curl -s http://localhost:9998/ui/auth_method` → expected **not**
   `"COSMIAN"` (falls back to whatever else is configured, or `"None"`).
2. `POST /ui/login_as` with any body → expected `500` with an error stating
   the Cosmian authentication server is not configured for the Web UI.
3. Bearer-token validation of already-issued tokens (existing `CosmianAuth`
   middleware on API routes) should be unaffected — only the UI login form is
   gated by the realm.

- [ ] Pass

---

## 3. Quick checklist summary

| # | Test | Result |
|---|------|--------|
| TC1 | Happy path login | ☐ |
| TC2 | No token reaches the browser (critical) | ☐ |
| TC3 | TOTP-protected account (correct + incorrect code) | ☐ |
| TC4 | Bad credentials rejected | ☐ |
| TC5 | `ChangePassword` surfaces actionable error | ☐ |
| TC6 | Authenticated API calls work end-to-end | ☐ |
| TC7 | Session persists across reload | ☐ |
| TC8 | Logout clears session + redirects to `/ui/login` | ☐ |
| TC9 | `/ui/auth_method` reports `COSMIAN` | ☐ |
| TC10 | Missing realm falls back gracefully | ☐ |

Report any failing case with: server log excerpt, browser console/network
screenshot, and the exact steps taken.
