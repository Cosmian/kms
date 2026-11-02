## Security

### Dependencies

- Bump the statically linked OpenSSL from 3.6.2 to 3.6.5, which fixes the fixable Critical CVEs reported by Grype
  (CVE-2026-63073, CVE-2026-34182, CVE-2026-75803). The FIPS provider is unchanged (OpenSSL 3.1.2, CMVP #4985).
  Build the Docker image runtime (curl, wget, bash, glibc, CA bundle) from nixos-26.05 instead of nixos-24.11, which
  removes the fixable CVEs in curl 8.11.0, openssl 3.3.2, nghttp2 1.64.0 and zlib 1.3.1 (COSMIAN-2026-049,
  [#1349](https://github.com/Cosmian/kms/issues/1349)).

## Bug Fixes

### Web UI

- Bump `vitest` to 5.0.5 (`@vitest/mocker` GHSA-xp26-3454-mjgp, GHSA-qxg6-89mg-rqv8) and override `zod` to `>=4.6.6`
  (GHSA-mrhx-c7xc-m3w5) in `ui/pnpm-lock.yaml`. Development dependencies only.

## CI

- `packaging-docker.yml`: new `scan-docker-image` job (`mise run test:docker-scan`) scans each published image with
  Syft and Grype, plus `Cargo.lock` and `ui/pnpm-lock.yaml`, and fails on fixable High or Critical findings. The SBOMs
  and Grype reports are uploaded as `image-scan-*` artifacts.
- `dependabot.yml`: add the `npm` ecosystem for `/ui` so that version updates bump the parent of a transitive
  dependency that security updates cannot fix.
