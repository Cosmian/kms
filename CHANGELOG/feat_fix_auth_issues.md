# Fix Auth Issues

## Features

### Web UI

- **Formalized authentication states**: the UI now explicitly handles four connection states — server unreachable, no authentication configured, mTLS (certificate) authentication, and JWT/OIDC authentication — with clear feedback for each case
- **No-auth warning banner**: when the KMS server is started without any authentication method, a persistent warning banner is shown informing users that anyone with network access can read all keys and that key creation/import is disabled
- **Improved CERT authentication UX**: the login page now shows a clear "CERT identity verification failed" error with instructions when no valid client certificate is provided, instead of silently looping

## Bug Fixes

### Web UI

- **E2E test race condition on page load**: fixed a race condition where `isAuthLoading` was initialized to `false`, causing the first React render to briefly show the "Cannot connect to KMS server" error page (which has no `submit-btn`); Playwright's `networkidle` could fire during this flash, causing sitemap tests to fail non-deterministically (notably PQC destroy and verify). Initializing `isAuthLoading` to `true` ensures the first render returns an empty fragment until the auth check completes.
- **Dev setup login crash**: fixed a crash in the development setup where the KMS was unable to complete the login flow despite valid credentials
- **OAuth interface fixes**: multiple fixes to the OAuth/OIDC interface, mostly affecting development-only scenarios
- **Removed misleading "JWT is enabled" message** from the UI

## Documentation

- **`configuration/ui.md`**: rewrote the Authentication Configuration section to document the four UI login states, reordered auth methods (OIDC before certificate), added a Certificate Authentication (mTLS) section with browser certificate installation steps, added a TOC, and linked to relevant server configuration settings (`kms_public_url`, `ui_index_html_folder`)
