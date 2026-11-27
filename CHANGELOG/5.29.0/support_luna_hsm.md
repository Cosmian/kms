# Thales Luna HSM support

## Bug Fixes

### Server

- Fix every HSM `Encrypt` failing on Thales Luna: the RSA-OAEP capability probe generated a
  temporary non-sensitive RSA key pair, which Luna rejects with `CKR_ATTRIBUTE_VALUE_INVALID`. As the
  failed probe was never cached, each request retried it under the cache lock, serializing all
  encryptions. The probe key is now sensitive (`base_hsm` `get_supported_oaep_hash`).
- Fix AES-GCM `Encrypt` on Thales Luna failing with "Failed to initialize message-based encryption":
  the Luna backend now uses classic `C_EncryptInit` AES-GCM instead of the PKCS#11 3.0 message API.
- HSM AES-GCM encryption/key wrapping now uses the IV returned by the HSM when it is appended to the
  output (`ciphertext || tag || iv`, Thales Luna in FIPS mode, firmware >= 7.9.3, 96-bit IV) instead
  of splitting the output at the wrong offset; a 16-byte HSM IV (older Luna firmware) is rejected.
- HSM `Encrypt` no longer re-queries the slot's supported algorithms (session open/close and
  `C_GetMechanismList`) on every request: the result is cached per slot. AES-GCM on Thales Luna went
  from a 288 req/s plateau to about 4,000 req/s.
- Fix creating non-sensitive (extractable) HSM keys on Thales Luna, which rejected the explicit
  `CKA_SENSITIVE=false` with `CKR_ATTRIBUTE_VALUE_INVALID`: the Luna backend now omits
  `CKA_SENSITIVE` and sets only `CKA_EXTRACTABLE`, like AWS CloudHSM.

### Docker image

- The KMS image ships the C++ runtime (`libstdc++`, `libgcc_s`, from the image's Nix toolchain) in
  `/usr/local/cosmian/lib/hsm`, on `LD_LIBRARY_PATH`: vendor PKCS#11 libraries such as Thales Luna
  `libCryptoki2_64.so` failed to load (`libstdc++.so.6: cannot open shared object file`).

### CLI

- `ckms bench --hsm` now creates HSM-resident AES keys and RSA/EC key pairs as sensitive for every
  HSM model: Thales Luna partitions rejected the previous non-sensitive (extractable) keys with
  `CKR_ATTRIBUTE_VALUE_INVALID`. Delegated benchmark reports of other HSM models now measure
  sensitive keys as well.
- `ckms bench --load --hsm` now destroys HSM keys created during protocol passes that end with no
  runnable operation (ttlv-bytes, jose); they were previously leaked on the HSM token.
- `ckms bench` gives every setup key a deterministic unique identifier, `bench-<purpose>` (e.g.
  `bench-load-json-sign-ecdsa-p256`), or `hsm::<slot>::bench-<purpose>` for HSM-resident keys, instead
  of a random UUID. A key left with that identifier by an earlier run or protocol pass is revoked
  and destroyed before being created again. Key-creation benchmarks keep unique identifiers.

### Tooling

- `mise run bench:hsm --hsm-model` accepts `luna`.
- `bench:hsm` no longer discards a caller-exported `BENCH_HSM_PASSWORD` (it was reset when
  `bench_helpers.sh` was sourced, so real HSMs got an empty PIN), and refuses to start when no
  password is available for a non-SoftHSM2 model, since failed logins count toward partition lockout.
- `bench:hsm`/`bench:load` honor `KMS_SKIP_BUILD=1`: they skip the Nix shell (`bench:hsm`) and cargo
  build and reuse prebuilt `target/<mode>/` binaries, so the benchmark can run on an HSM host that
  has no Rust toolchain.
- `.github/reusable_scripts/prepare_luna.sh` installs the Thales Luna Client runtime (from the Thales
  tarball) and, optionally, the NTLS configuration delivered by the HSM administrator, on a host or
  in a container image.

### Tests

- Thales Luna PKCS#11 test suite (`luna_pkcs11_loader`, `luna` feature): 25 tests mirroring the
  Proteccio suite. After each test, even a failing or panicking one, only the new objects whose
  `CKA_ID` carries the shared tests' `kms-test-` prefix are destroyed, so other users' objects on a
  shared partition, existing or created during the run, are left alone.
- Shared HSM tests create every object with a `kms-test-<uuid>` `CKA_ID`, and `rsa_key_wrap`
  destroys the key it unwraps.
- The shared `list_objects` HSM test no longer destroys every object on the slot: it counts only the
  objects it creates.

## Documentation

- Thales Luna: correct KMS configuration (`hsm_model = "luna"`, `hsm_slot`, `hsm_password`) in the
  Luna guides, Luna-specific behavior (sensitive keys, AES-GCM, FIPS IV, several appliances via
  `ChrystokiConfigurationPath`), and `luna` added to the HSM model lists, server CLI and TOML templates.
- Benchmark reports for Thales Luna 1/2 and Proteccio, with HSM characteristics pages, kept out of the
  mdBook navigation: the Luna setup page no longer links to them.
- Thales Luna on Kubernetes: official KMS image unmodified, Luna Client runtime copied by an init
  container from a client image, configuration and credentials from Secrets; Helm values documented.
- Luna and benchmark pages anonymized; the host-specific Luna 2 configuration and testing procedure
  pages are replaced by `prepare_luna.sh` and the Luna quick reference.
- Thales Luna: PKCS#11 call logging with Thales `cklog` (`LUNA_PKCS11_LIB` pointing to
  `libcklog2.so`), partition activation check without login, no environment script required; HSM
  section in the Kubernetes Helm page.
- HSM algorithm support page: Thales Luna and GCP Cloud HSM columns in every table (Luna rows from
  the Luna test suite, every curve and digest confirmed in the run log), a "not tested" legend
  entry, and CI coverage stated per model.
