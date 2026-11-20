## Features

### CLI
- Add `ckms ssh sign` for signing OpenSSH user certificates with a KMS-managed SSH CA.
- Add `ckms ssh ca create|set|public-key` and `ckms ssh role put` to manage the SSH CA and roles; `ssh ca create --sensitive` creates a non-exportable CA key (required on an HSM) and unsupported curves are refused before any key is created.
- Add `ckms ssh sign --generate-key PATH` to generate a local ECDSA P-256 key pair and certificate; clarify the `--principal` help.
- Add `ckms password` for generating passwords through the KMS.

### Web UI
- Add SSH certificate signing and password generation pages.
- Add an `SSH CA & Roles` page to create the SSH CA (new or existing EC key, optionally sensitive), show its public key and save roles (default lifetime 15m, maximum 1h).
- Generate the SSH key pair in the browser on the certificate page.
