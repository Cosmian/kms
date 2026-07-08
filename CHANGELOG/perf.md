## Features

### Server / Performance

- Introduce an **in-memory object cache** (`ObjectCache`) backed by
  [`moka`](https://github.com/moka-rs/moka) — lock-free concurrent reads via a
  sharded `HashMap` giving linear throughput scaling with CPU count.
  Each entry stores an `Arc<ObjectWithMetadata>` together with a TTLV fingerprint
  for stale-entry detection; TTI eviction and LRU capacity are delegated to moka.
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

- Add a dedicated **CEK cache** (`cek_cache`) for the JOSE `/encrypt` and
  `/decrypt` endpoints, eliminating repeated key-fetch round-trips on hot paths
  such as encryption-as-a-service workloads.
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

- Add `--http-workers` CLI flag (env: `KMS_HTTP_WORKERS`) to control the number
  of actix-web HTTP worker threads. Defaults to `available_parallelism()` (all
  logical CPUs). Renamed from the undocumented `server_workers` TOML key; all
  config templates updated accordingly.
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

### TTLV Wire Format

- Add a binary TTLV bytes serializer/deserializer (`TTLVBytesSerializer` /
  `TTLVBytesDeserializer`) for zero-copy wire encoding, reducing per-request
  allocation compared to the JSON TTLV path.
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

- Fix tag-name resolution fallback: `write_tag` now falls through to
  `lookup_enum_code` when `from_str` fails, handling serde PascalCase renames
  (e.g. `CertificateSubjectCn` → `CertificateSubjectCN`).
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

### CLI / Benchmarking

- Add `ckms bench` subcommand with sub-commands for KMIP TTLV bytes throughput,
  KMIP TTLV JSON throughput, JOSE encrypt/decrypt, and HTTP load benchmarks.
  ([#1016](https://github.com/Cosmian/kms/pull/1016))

### Documentation

- Add **Object & Unwrapped Caches** reference page
  (`configuration/object-cache.md`) and wire it into the MkDocs nav.
- Add benchmark reports and CPU-scaling flamegraph pages under the new
  **Benchmarks** nav section.

## Build

- `crate/crypto/build.rs`: emit `cargo:rerun-if-env-changed=CFLAGS` so the
  OpenSSL build is correctly invalidated when the C compiler flags change.

---
