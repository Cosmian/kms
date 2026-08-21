## Bug Fixes

### Nix / Docker packaging

- **Docker images now include `grep`**: the `kms-fips`/`kms` Docker images were missing the
  `grep` binary (not provided by `coreutils`), causing any in-image script relying on `grep`
  to silently fail with "command not found". This broke the CA bundle validity check
  (`SSL_CERT_FILE`/OIDC prerequisite, regression test for issue #1132), which always reported
  `0 certificates` regardless of the actual CA bundle content, since the failed `grep`
  invocation was masked by a `2>/dev/null || echo 0` fallback. Added `pkgs.gnugrep` to the
  image's runtime environment in `nix/docker.nix`.
- **`fakeRootCommands` no longer fails on Nix store symlinks**: `buildLayeredImage`'s
  `contents` merge (via `buildEnv`/`lndir`) keeps a directory as a symlink into the read-only
  Nix store whenever only a single input derivation contributes that subtree (e.g.
  `usr/local/bin`, provided only by the PKCS#11 `ckms-bin` derivation). Any write into such a
  path from `fakeRootCommands` failed with "Permission denied" even under fakeroot, breaking
  every Docker packaging CI job. Generalized the previous `/etc`-only fix into a reusable
  `ensure_writable_dir` helper applied to every directory `fakeRootCommands` writes into.
