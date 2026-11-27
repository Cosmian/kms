# CHANGELOG — feat/automate_key_rotation

## Features

### Server / Auto-rotation scheduler

- Implement `run_auto_rotation()` in `crate/server/src/core/operations/auto_rotate.rs`:
  queries `find_due_for_rotation(now)` via the database backend, routes symmetric keys
  to `ReKey` and private keys to `ReKeyKeyPair`, and skips HSM-resident keys (UID prefix
  `hsm::`) since the KMS cannot generate new key material inside an HSM ([#970](https://github.com/Cosmian/kms/pull/970))
- Implement `dispatch_renewal_warnings()`: queries keys due within the next 30 days and
  emits `info!` log entries at the [30, 7, 1]-day warning thresholds as a skeleton for the
  forthcoming SMTP notification layer (PR #971) ([#970](https://github.com/Cosmian/kms/pull/970))
- Add `days_until_next_rotation(attrs, now)` pure function: computes whole days until the
  next rotation deadline using `rotate_date + interval` (if the key has already been rotated
  at least once) or `initial_date + rotate_offset + interval` (first rotation) ([#970](https://github.com/Cosmian/kms/pull/970))

### Metrics

- Add `kms.key.auto_rotation` `OTel` counter to `OtelMetrics` — incremented on every
  auto-rotation attempt with labels `uid`, `algorithm`, and `outcome` (`"success"` /
  `"failure"`) ([#970](https://github.com/Cosmian/kms/pull/970))

## Testing

- Add 7 unit tests for `days_until_next_rotation()` covering: overdue key (>1 day),
  same-day key, future key, `rotate_date` precedence, `rotate_offset` shift, missing
  interval, and zero interval ([#970](https://github.com/Cosmian/kms/pull/970))
- Add 2 integration tests in `auto_rotate.rs`:
  - `test_auto_rotation_rotates_due_symmetric_key`: creates an AES-256 key past its
    rotation deadline in the in-process SQLite database, calls `run_auto_rotation()`,
    and asserts the original key transitions to `Deactivated` with a
    `ReplacementObjectLink` to the successor key ([#970](https://github.com/Cosmian/kms/pull/970))
  - `test_auto_rotation_skips_hsm_keys`: verifies that a key with an `hsm::` UID prefix
    remains `Active` after `run_auto_rotation()` ([#970](https://github.com/Cosmian/kms/pull/970))
