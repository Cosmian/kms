# Fix Auth Issues

## Features

### Web UI

- **Formalised connection states**: the UI now explicitly handles exactly four states — no KMS server reachable, server with no auth configured, mTLS (certificate) auth, and JWT/OIDC auth
- **No-auth warning banner**: displays a clear banner when the KMS is started without authentication
- **mTLS login page**: shows a clear error when no valid client certificate is provided, instead of silently looping

## Bug Fixes

### Web UI

- **E2E test race condition**: fixed non-deterministic sitemap test failures caused by the initial render briefly showing the error page before auth resolved
- **Dev setup login crash**: fixed a crash in the dev setup where the KMS was unable to complete the login flow despite valid credentials
- **OAuth/OIDC fixes**: multiple fixes to the OAuth interface, mostly dev-only scenarios
- **Removed misleading "JWT is enabled" message**

## Documentation

- **`configuration/ui.md`**: documented the four UI connection states and the Certificate Authentication (mTLS) setup
