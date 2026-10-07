# This directory provides

- base Rust PKCS#11 bindings and traits that can be used to create a PKCS#11 client or a
  [PKCS#11](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html)
  provider
- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS

[PKCS##11 documentation](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf)

1. `module` crate

    The module crate exposes traits to create a PKCS#11 library. It is a modified fork of
    the `native_pkcs11` crate from Google. The `module` crate is used to build the `provider` PKCS#11 library.

2. `provider` crate

    The provider crate is a PKCS#11 library that interfaces the KMS. It provides a PKCS#11
    library for applications such as LUKS and is built from the `module` crate.

3. `bench` subcommand

    The provider crate's compiled shared library can be benchmarked via
    `ckms pkcs11 bench --help` (driven through `mise bench:pkcs11`).

## External battle tests

The `mise run test:pkcs11:tool` task runs the HSM-KEK `pkcs11-tool` regression suite, then
starts a fresh plain KMS server and runs the vendor-neutral
[`pkcs11-check`](https://github.com/mingulov/pkcs11-check) smoke profile. The external suite is
non-FIPS because its PQC coverage requires the non-FIPS provider. Use `--marker ""` for the full
available corpus after downloading vector data with `pkcs11-check fetch-data all`.

Reports are written to `test_reports/` as JSON, JUnit XML, and sidecar quality artifacts. Provider
`xfail` and `fail` findings are evidence, not certification verdicts; crashes, timeouts, incomplete
runs, and critical findings fail the task. See [the battle-test skill](../../../.github/skills/pkcs11-check.md)
for report interpretation and baseline comparison.

The following implementation boundaries are intentional and should be cross-referenced when
triaging findings:

| Area | Current behavior |
| --- | --- |
| Multipart streaming | Not supported by the provider; one-shot operations are tested. |
| Key wrap/derive | Not advertised by the provider; related checks are expected to skip or xfail. |
| Token write operations | The KMS-backed token is effectively write-protected; creation is KMS-driven. |
