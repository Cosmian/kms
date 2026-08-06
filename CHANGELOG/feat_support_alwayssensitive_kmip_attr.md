## Features

- **KMIP `AlwaysSensitive` attribute (KMIP 2.1 §4.3)**: the server now creates and
  manages the `AlwaysSensitive` attribute on Symmetric Keys, Private Keys and Secret
  Data. It is set to `True` at creation/registration iff the object is `Sensitive`, and
  is permanently set to `False` once `Sensitive` is ever set to `False` (even if
  `Sensitive` is later set back to `True`).
- `ckms attributes set` gains a `--sensitive <true|false>` flag; `ckms attributes get -a
  AlwaysSensitive` now reports the value. The Web UI exposes `Always Sensitive`
  (read-only) in the attribute Get selector.

## Security

- **`AlwaysSensitive` is server-managed**: clients can no longer add, set, modify or
  delete it via the `AddAttribute`, `SetAttribute`, `ModifyAttribute` or
  `DeleteAttribute` operations — such requests are rejected with
  `Attribute_Read_Only`. This prevents tampering with the sensitivity history of a
  managed object.
