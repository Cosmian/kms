## Features

- **KMIP `AlwaysSensitive` attribute (KMIP 2.1 §4.3)**: the server now creates and
  manages the `AlwaysSensitive` attribute on Symmetric Keys, Private Keys and Secret
  Data. It is set to `True` at creation/registration iff the object is `Sensitive`, and
  is permanently set to `False` once `Sensitive` is ever set to `False` (even if
  `Sensitive` is later set back to `True`).
- `ckms attributes set` gains a `--sensitive <true|false>` flag; `ckms attributes get -a
  AlwaysSensitive` now reports the value. The Web UI exposes `Always Sensitive`
  (read-only) in the attribute Get selector.

## Bug Fixes

- **KMIP 1.x attribute version gating**: the server no longer returns attributes that the
  client's protocol version does not define. `Get`, `GetAttributes` and
  `GetAttributeList` responses are now filtered against the version in which each
  attribute was introduced (OASIS KMIP Specification, Section 3 "Attributes"):
  `Fresh` (KMIP 1.1 §3.34); `Alternative Name` (KMIP 1.2 §3.40), `Original Creation Date`
  (KMIP 1.2 §3.43); `Random Number Generator` (KMIP 1.3 §3.44); `Description`
  (KMIP 1.4 §3.46), `Comment` (KMIP 1.4 §3.47), `Sensitive` (KMIP 1.4 §3.48),
  `Always Sensitive` (KMIP 1.4 §3.49), `Extractable` (KMIP 1.4 §3.50) and
  `Never Extractable` (KMIP 1.4 §3.51). Filtering applies to explicitly requested
  attributes too, since a pre-1.4 client cannot decode an attribute it does not know.
  Previously, KMIP 1.0–1.3 clients (e.g. Synology DSM, PyKMIP, Percona) could receive
  `Always Sensitive`, `Original Creation Date` or `Random Number Generator` and fail to
  parse the response.
- **`Never Extractable` was never serialized**: converting a KMIP 2.1 `Attributes`
  structure into the attribute list used by KMIP 1.x responses dropped
  `never_extractable` entirely, so the attribute was invisible to every client despite
  KMIP 2.1 §4.33 requiring it to always have a value. It is now returned when requested.

## Security

- **`AlwaysSensitive` is server-managed**: clients can no longer add, set, modify or
  delete it via the `AddAttribute`, `SetAttribute`, `ModifyAttribute` or
  `DeleteAttribute` operations — such requests are rejected with
  `Attribute_Read_Only`. This prevents tampering with the sensitivity history of a
  managed object.
- **Internal tagging attribute no longer leaks**: the Cosmian-internal tag vendor
  attribute is now stripped from every KMIP 1.x `GetAttributes` response. Previously the
  scrub was skipped on some request shapes.

## Testing

- **Go-based KMIP compliance tests** (`ovh/kmip-go`, KMIP 1.0–1.4): new external
  interop test suite in `.mise/scripts/kmip-go/` — 16 tests validate the server against
  an independent Go KMIP implementation. Covers DiscoverVersions, Query, AES-256
  lifecycle (all 5 versions 1.0–1.4), RSA-2048/EC-P256 key pairs, Locate, batch ops,
  AES-GCM encrypt/decrypt, RSA-PSS sign/verify, and — critically — the version-gating
  of KMIP 1.4+ attributes (`AlwaysSensitive`, `NeverExtractable`, `Extractable`,
  `Sensitive`, `Fresh`) across all protocol versions. Run with `mise run test:kmip-go`.

## KMIP conformance fixes found by the ovh/kmip-go test suite

The Go test suite decodes every attribute into a strongly typed value using the
TTLV type mandated by the specification, which makes it a stricter oracle than the
XML profile vectors (those compare decoded Rust structs and are blind to
wire-type errors). It surfaced the following server bugs:

- **`Lease Time` was encoded as TTLV `Integer` instead of `Interval`**
  (KMIP 1.4 §3.20 Table 99, KMIP 2.1 §4.29 Table 88). Strictly typed clients
  rejected every `Get Attributes` response carrying it. A new `Interval` TTLV
  newtype now emits the correct primitive.
- **`RNG Parameters.Cryptographic Length` was encoded as `LongInteger` instead of
  `Integer`** (KMIP 1.4 Table 39, KMIP 2.1 Table 388), making the
  `Random Number Generator` attribute undecodable.
- **`DeleteAttribute` responses omitted the deleted `Attribute`**, which
  KMIP 1.4 §4.16 Table 205 requires (KMIP 2.1 §6.1.13 Table 203 requires only the
  Unique Identifier). The truncated payload could not be decoded by strict clients.
- **`DeleteAttribute` by name was a silent no-op for most attributes**: the
  name-based branch handled only 9 tags and ignored the rest, so deleting
  `Object Group`, `Contact Information`, `Description` or `Comment` returned
  Success without deleting anything. Unknown tags are now rejected explicitly.
- **Custom attributes could not be deleted by name**: the KMIP 1.x → 2.1 request
  conversion split `x-attribute1` into vendor `x` / name `attribute1`, whereas
  `AddAttribute` stores it as vendor `KMIP1` / name `x-attribute1`. The lookup
  always missed, so the delete silently did nothing.
- **`Comment` was write-only**: it could be added and modified but was never
  returned by `Get Attributes` (KMIP 1.4 §3.47).

## Security

- **Read-only attributes could be rewritten by any client.** `ModifyAttribute`
  enforced its read-only guard on only three attributes. A client could change
  `Initial Date` (verified: back-dated to 1999), `Cryptographic Length` (verified:
  a 256-bit AES key reported 64), `Object Type`, `Last Change Date`,
  `Original Creation Date`, `Fresh`, `Digest`, `Unique Identifier` and
  `Never Extractable` — rewriting server-managed provenance and defeating audit
  trails. All attributes marked "Modifiable by client: No" in their KMIP Attribute
  Rules table are now rejected with `Attribute_Read_Only`, and the equivalent set
  marked "Deletable by client: No" is rejected by `DeleteAttribute`.
