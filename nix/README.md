# Nix: OpenSSL 3.1.2 (FIPS) for KMS

This folder provides:
- `openssl-3_1_2-fips.nix`: static OpenSSL 3.1.2 with FIPS provider
- `shell-hook.sh`: minimal env for reproducible builds
- `inner_build.sh`: builds and validates KMS inside nix-shell

Use: run the repository script `bash .github/scripts/cargo_build.sh`.
