# Audit events

Every audit event has the same fields, whether it is an ordinary KMIP operation or one of the
system events described below. `ckms audit export` and `ckms audit verify` both read this shape.

## Fields

| Field         | Type                                     | Nullable | Description                                                                                                                                      |
| ------------- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`          | `integer`                                | No       | Monotonically increasing row counter, starting at 0 for each chain (for each chain generation with the PostgreSQL backend).                    |
| `timestamp`   | `string` (RFC 3339 / UTC)                | No       | Wall-clock time of the KMIP operation.                                                                                                           |
| `operation`   | `string`                                 | No       | KMIP operation name, e.g. `"Create"`, `"Encrypt"`, `"Destroy"`. Batch requests produce a `+`-joined name such as `"Create+Encrypt"`.             |
| `user`        | `string`                                 | No       | Authenticated username. `"unauthenticated"` when no identity was presented (e.g. 401 paths). `"server"` for a system event.                      |
| `object_uid`  | `string` or `null`                       | Yes      | KMIP `UniqueIdentifier` of the object involved. `null` when unavailable (e.g. failed auth, batch, system event).                                 |
| `algorithm`   | `string` or `null`                       | Yes      | Cryptographic algorithm, e.g. `"AES"`, `"RSA"`. `null` when the operation carries no algorithm.                                                  |
| `client_ip`   | `string` or `null`                       | Yes      | The direct TCP peer address, or the `X-Forwarded-For` value when the request comes from a trusted proxy. See [Client IP and reverse proxies](./audit-logs.md#client-ip-and-reverse-proxies). |
| `result`      | `"Success"` or `{"Failure": "<reason>"}` | No       | Outcome of the operation.                                                                                                                        |
| `duration_ms` | `integer`                                | No       | Wall-clock duration of the operation in milliseconds.                                                                                            |
| `request_id`  | `string` (UUID) or `null`                | Yes      | Correlation ID across operations from the same request. `null` for system events.                                                                |
| `details`     | `string` or `null`                       | Yes      | Structured JSON payload attached to a system event. `null` for ordinary KMIP events. See [System events](#system-events).                        |
| `prev_hash`   | `string` (64 hex chars)                  | No       | SHA-256 of the previous row's canonical bytes. All-zeros for the first row (`id = 0`).                                                           |
| `row_hash`    | `string` (64 hex chars)                  | No       | SHA-256 of this row's canonical bytes (including `prev_hash`).                                                                                   |

!!! note "PostgreSQL backend"
    The PostgreSQL backend stores the `user` field in a `username` column. `ckms audit export`
    from a PostgreSQL source adds two fields, `instance_id` and `chain_generation`, to every JSON
    event; the stored event and its hashes are unchanged. Because `id` restarts in each generation
    and instance, identify an event by `(instance_id, chain_generation, id)`. See
    [SIEM integration](./siems.md#postgresql-source-attribution).

**Example event** (file backend):

```json
{
  "id": 4,
  "timestamp": "2026-05-06T20:31:42.321328507Z",
  "operation": "Encrypt",
  "user": "admin",
  "object_uid": "417fe2de-827d-48d0-8d51-851bec315b76",
  "algorithm": "AES",
  "client_ip": "127.0.0.1",
  "result": "Success",
  "duration_ms": 1,
  "request_id": "c1f728c0-85f2-498c-8f47-9759d57a2745",
  "prev_hash": "e492c0f02860bc6c428259d44414651eda3aaaee2f48eb857144c940ac0fe909",
  "row_hash": "699a2837830af4a26fe79aeb48509fc707507e514da5850d953366a14e730c38"
}
```

---

## System events

The KMS appends these events for its own recovery and operational actions. They join the same
hash chain as ordinary KMIP events, with `user` set to `"server"`.

| Event                        | Written when                                                                            | `result`                                     | `details`                                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `audit:eviction`             | One or more events were dropped because the writer's queue was full.                    | `Failure`, with the count of dropped events. | `null`                                                                                             |
| `audit:size-cap-reached`     | The file backend's `--audit-file-max-size-bytes` cap was reached.                       | `Failure`                                    | `null`                                                                                             |
| `audit:torn-write-recovered` | File backend only: an incomplete trailing row was found and discarded after an ungraceful restart. | `Success`                         | `bytes_discarded` and `offset` of the discarded fragment.                                          |
| `audit:reanchor`             | The KMS started a fresh chain after finding the previous one corrupted (seal-and-roll). | `Success`                                    | `reason` (see [Reanchor reasons](#reanchor-reasons)) plus backend-specific evidence fields, described in [File backend](./audit-file-backend.md#startup-and-recovery) and [PostgreSQL backend](./audit-postgresql-backend.md#startup-and-recovery). |

### Reanchor reasons

Both backends classify the corruption that triggered a seal-and-roll with one of these values in
the `reason` field of the `audit:reanchor` event's `details`:

| Reason          | Meaning                                                                       |
| --------------- | ----------------------------------------------------------------------------- |
| `hash_mismatch` | A complete row whose own hash doesn't match its stored bytes.                 |
| `broken_link`   | A row that verifies on its own but doesn't chain to its predecessor.          |
| `unparsable`    | A row or column doesn't decode as an audit event at all.                      |
| `id_overflow`   | A valid tail row at the maximum event ID: continuing in place would overflow. |

---

## Hash chain

Every event includes a SHA-256 hash chain that makes tampering detectable offline.

The hash is computed over a canonical byte sequence of the event's fields, in this order:
`prev_hash || id || timestamp || operation || user || object_uid || algorithm || client_ip || result || duration_ms || request_id || details`

`request_id` and `details` are each included only when present, so events written before a field
was added still hash to the same bytes.

`prev_hash` of the first event (`id = 0`) is the 32-byte all-zeros sentinel.

Any modification to a field in any row, including reordering rows, deleting rows, or appending
forged rows, breaks at least one `prev_hash → row_hash` link and is detected by
`ckms audit verify`.
