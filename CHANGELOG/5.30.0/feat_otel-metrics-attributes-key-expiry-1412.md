## Features

### Observability

- Label `kms.keys.active.count` with `object_type`, `algorithm`, `key_length` and `state` (one series per combination, capped at 1000 with an `__overflow__` series). Dashboards must aggregate with `sum(kms_keys_active_count)` to get the total ([#1412](https://github.com/Cosmian/kms/issues/1412))
- Add the `kms.keys.expiring_soon.count` gauge: PreActive and Active keys whose `DeactivationDate` falls within the next 7, 30 or 90 days (`days_until_expiry` label, cumulative windows) ([#1412](https://github.com/Cosmian/kms/issues/1412))
- Add an `outcome` label (`success` · `error`) to `kms.kmip.operations.total` and `kms.hsm.operations.total` ([#1412](https://github.com/Cosmian/kms/issues/1412))
- Update the bundled Grafana dashboard to aggregate the newly labelled series

## Documentation

- Document the new metric labels and gauge, and how to tag keys with KMIP vendor attributes for reporting, in `monitoring/OTLP_METRICS.md` and the OTLP telemetry configuration page

---

Closes #1412
