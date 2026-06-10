## Features

- **`ckms login cosmian`**: implement Cosmian authentication server login via `POST /login?realm=<realm>` with HTTP Basic credentials (`Authorization: Basic <base64(username:password)>`).
  - Add `CosmianLoginConfig` struct (`server_url`, `realm`) to `cosmian_kms_client`.
  - Add `cosmian_conf` field to `HttpClientConfig` (separate from `oauth2_conf`).
  - Add `cosmian_login` async helper in the HTTP client library.
  - `ckms login cosmian --username <u> --password <p>` CLI subcommand.
