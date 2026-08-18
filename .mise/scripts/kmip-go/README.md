# KMIP Compliance Tests — ovh/kmip-go

Go-based KMIP 1.0–1.4 compliance tests for the Eviden KMS server, using the independent
[ovh/kmip-go](https://github.com/ovh/kmip-go) client library.

## Roles

| Component | Role |
|-----------|------|
| **Eviden KMS** | **KMIP Server** (socket on port 15696) |
| **ovh/kmip-go client** | **KMIP Client** (sends requests, asserts responses) |

## Run

```bash
# Via MISE (builds KMS, starts server, runs tests, cleans up)
mise run test:kmip-go

# Directly (KMS must already run on port 15696)
KMIP_GO_REPO_ROOT=$(git rev-parse --show-toplevel) go test -v -count=1 ./...
```

## Files

| File | Purpose |
|------|---------|
| `helpers_test.go` | `newClient`, `tctx`, `versionName`, `allVersions`, `pre14Versions`, `createAES256`, `activateKey`, `cleanupKey`, `getAttrList`, `hasAttr`, `sanitiseName` |
| `compliance_test.go` | Core lifecycle (AES-256 for all KMIP 1.0–1.4), Query, Batch |
| `lifecycle_test.go` | Key state transitions, usage-mask enforcement |
| `version_compliance_test.go` | Version-gating: assert KMIP 1.4+ attrs absent/present by version |
| `attributes_test.go` | All 49 attributes: decodability, TTLV wire types, Attribute Rules (read-only / writable), custom attributes, Locate |
| `crypto_test.go` | AES-GCM encrypt/decrypt, RSA-PSS sign/verify, EC key pair |
| `locate_test.go` | Locate operation: empty-result, name-filter, pagination |
| `operations_test.go` | ReKey, Import, Register, Hash, Export, multi-operation Batch |
| `split_key_test.go` | CreateSplitKey (§4.38) + JoinSplitKey (§4.39): share metadata, full roundtrip, threshold enforcement, Query advertisement |

## Key assertion: version-gating of KMIP 1.4+ attributes

Attributes `AlwaysSensitive`, `NeverExtractable`, `Extractable`, `Sensitive` were
**introduced in KMIP 1.4** (OASIS spec §3.48–3.51). The server must NOT return them
to KMIP 1.0–1.3 clients.

The `TestGetAttributeList_KMIP14Attrs_AbsentInPre14` and
`TestGetAttributeList_KMIP14Attrs_PresentIn14` tests verify this directly.

## Key assertion: TTLV wire types

`ovh/kmip-go` decodes each attribute into a distinct Go type, so it rejects an
`Integer` where the spec mandates an `Interval`. The repository's own XML profile
vectors compare *decoded Rust structs* and cannot see such a mismatch — which is
what makes this suite an independent oracle rather than a duplicate.

`attributes_test.go` found seven server bugs this way, including `Lease Time`
encoded as `Integer` instead of `Interval` (KMIP 1.4 §3.20 Table 99) and
`ModifyAttribute` accepting changes to read-only attributes such as `Initial Date`
and `Cryptographic Length`. See the full documentation for the complete list.

## Adding a test

- New attribute introduced after KMIP 1.0 → add it to `attributeMinorVersion()`.
- Attribute marked `Modifiable by client: No` → add it to `readOnlyAttrs`.
- Attribute marked `Modifiable by client: Yes` → add it to `writableAttrs`.
- New KMIP operation not yet in the `payloads` package → define local payload
  structs implementing `kmip.OperationPayload`, register them in `init()` with
  `kmip.RegisterOperationPayload`, then use `client.Request(ctx, &MyPayload{})`.
  See `split_key_test.go` for a worked example (CreateSplitKey / JoinSplitKey).

Always cite the specification section (e.g. `KMIP 1.4 §3.20`) in the test message;
the spec HTML files live under `kmip/` in this repository.

## Full documentation

See [documentation/docs/integrations/kmip_go.md](../../../documentation/docs/integrations/kmip_go.md)
or the rendered documentation site under **Integrations → KMIP compliance tests**.
