## Bug Fixes

### Hardening

- Bound client-controlled KMIP parameters ([#1489](https://github.com/Cosmian/kms/issues/1489)):
  `GET /certificates/{id}/crl` rejects `validity_days` above 365 (HTTP 422) instead of panicking;
  `RotateInterval`/`RotateOffset` must be KMIP Intervals (0..=4294967295 s) and out-of-range
  stored schedules are skipped by the auto-rotation scheduler instead of crashing it;
  `DeriveKey` limits the derived length to 8–8192 bits and PBKDF2 work (iterations × output blocks)
  to 10,000,000; PBKDF2 and key-pair generation run on the blocking pool; FPE data and tweak are
  limited to 4096 bytes; `CreateSplitKey` refuses objects larger than 8 KiB.

---

Closes #1489
