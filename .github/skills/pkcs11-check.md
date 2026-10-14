PKCS#11 external battle-test workflow and report interpretation.

## When to use

Use the `pkcs11-check` battle tests when changing `crate/clients/pkcs11/`, the PKCS#11 MISE
scripts, or provider configuration. The suite is an independent client, not a replacement for the
module/provider unit tests or the raw ABI harness.

## Run locally

```bash
mise run test:pkcs11:tool
```

The task always runs both suites in order:

1. HSM-KEK `pkcs11-tool` and raw-ABI regression tests.
2. A fresh plain KMS server with `pkcs11-check`'s `smoke` marker.

The task defaults to non-FIPS because the external corpus includes PQC mechanisms. Run the full
available corpus only after fetching its data:

```bash
pkcs11-check fetch-data all
mise run test:pkcs11:tool --marker ""
```

The pinned dependency is `.mise/scripts/test/requirements-pkcs11-check.txt` (`0.2.2`). The runner
installs it in `target/pkcs11-check-venv` and does not modify the system Python environment.

## Reports

The runner writes these files below `test_reports/`:

- `pkcs11_check_<marker>.json`: consolidated results and summary counts.
- `pkcs11_check_<marker>.xml`: JUnit output for CI.
- `report.jsonl`, `coverage.json`, and `quality.json`: machine-readable sidecars emitted by the
  JSON run.

`passed` means the observed behavior matched the test oracle. `skipped` usually means the provider
does not advertise the mechanism. `xfailed` records an expected provider deviation, commonly an
unsupported curve or key size multiplied across vector cases. `failed` is evidence for triage and
is not itself a certification claim.

The task safety gate fails on `error`, `crashed`, `timeout`, incomplete coverage, or a
`CRITICAL` finding in `report.jsonl`. It intentionally does not fail solely on ordinary provider
`xfail` or `fail` findings. Supply `PKCS11_CHECK_XFAIL_BASELINE` to the Bash runner to compare
the xfail count with a JSON baseline; the allowed variance is the greater of five cases or 10%.

## Known boundaries

| Area | Interpretation |
| --- | --- |
| Multipart streaming | Provider support is intentionally absent; related checks should skip or xfail. |
| Key wrap/derive | These mechanisms are not advertised by the KMS-backed provider. |
| Token write | Token mutation is not the provider's storage model; KMS operations own object creation. |
| Full vectors | `fetch-data all` downloads a large external corpus and is not part of the default smoke run. |

`pkcs11-check` is a hardening tool. Its results do not establish FIPS 140-3, Common Criteria, or
any other compliance certification.
