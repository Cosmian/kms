# Fix Auth Issues

## Features

### Web UI

- **Formalized authentication states**: the UI now explicitly handles four connection states — server unreachable, no authentication configured, mTLS (certificate) authentication, and JWT/OIDC authentication — with clear feedback for each case
- **No-auth warning banner**: when the KMS server is started without any authentication method, a persistent warning banner is shown informing users that anyone with network access can read all keys and that key creation/import is disabled
- **Improved CERT authentication UX**: the login page now shows a clear "CERT identity verification failed" error with instructions when no valid client certificate is provided, instead of silently looping

## Bug Fixes

### Web UI

- **Dev setup login crash**: fixed a crash in the development setup where the KMS was unable to complete the login flow despite valid credentials
- **OAuth interface fixes**: multiple fixes to the OAuth/OIDC interface, mostly affecting development-only scenarios
- **Removed misleading "JWT is enabled" message** from the UI

## Documentation

- **`configuration/ui.md`**: rewrote the Authentication Configuration section to document the four UI login states, reordered auth methods (OIDC before certificate), added a Certificate Authentication (mTLS) section with browser certificate installation steps, added a TOC, and linked to relevant server configuration settings (`kms_public_url`, `ui_index_html_folder`)
