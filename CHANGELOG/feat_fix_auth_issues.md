# Fix Auth Issues

## Features

### Web UI

- **Formalised connection states**: the UI now explicitly handles five states — DEV unrestricted mode (`VITE_DEV_MODE=true`), no KMS server reachable, server with no auth configured, mTLS (certificate) auth, and JWT/OIDC auth (including combined JWT+mTLS)
- **No-auth warning banner**: displays a clear banner when the KMS is started without authentication
- **mTLS login page**: shows a clear error when no valid client certificate is provided, instead of silently looping

## Bug Fixes

### Server

- **Stale session cookie warnings**: eliminated repeated `actix_session` WARN logs on server restart — the session cookie key is now derived deterministically from the public URL instead of being regenerated randomly each start; configure `ui_session_salt` for multi-instance deployments
- **Header crash on partial server-info response**: guard `serverInfo?.hsm` before accessing `hsm.configured` to prevent a runtime crash when the `/server-info` response is missing the HSM field

### Web UI

- **E2E test race condition**: fixed non-deterministic sitemap test failures caused by the initial render briefly showing the error page before auth resolved
- **Dev setup login crash**: fixed a crash in the dev setup where the KMS was unable to complete the login flow despite valid credentials
- **OAuth/OIDC fixes**: multiple fixes to the OAuth interface, mostly dev-only scenarios
- **Removed misleading "JWT is enabled" message**

## Documentation

- **`configuration/ui.md`**: documented the five UI connection states and the Certificate Authentication (mTLS) setup

## CI

### Windows

- **`test_ui.ps1`**: fix KMS log file paths — use `$RUNNER_TEMP` (with local fallback) and names `kms-stdout.log` / `kms-stderr.log` to match the `Upload logs on failure` workflow step so KMS server output is actually captured on failures
- **`test_ui.ps1`**: use `--frozen-lockfile` for `pnpm install` (mirrors Linux `test_ui.sh`) to ensure reproducible builds without inadvertent package updates
