## Build

### Maintenance
- Remove the legacy `.mise/scripts/nix.sh` dispatcher (#1420): `mise run build:docker` now calls `nix_build docker-image-<variant>` directly (`--variant`, `--load` unchanged; the unused `--test`/`--force` options and tarball reuse are gone). `release.sh` no longer edits it, and stale `nix.sh … test <type>` hints now point to the matching `mise run test:…` tasks
