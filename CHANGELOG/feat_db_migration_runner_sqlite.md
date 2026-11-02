## Features

### Database

- Add a shared version-sequenced migration runner and wire SQLite into it, with resumable wrapping-key ID and certificate serial-tag backfills, per-step completion markers and persisted version checkpoints ([#1270](https://github.com/Cosmian/kms/issues/1270), [#1271](https://github.com/Cosmian/kms/issues/1271)).
- Serialize SQLite startup with a sidecar file lock, retrying every 500 ms for up to 31 minutes. Refuse databases stamped by a newer KMS version before running schema DDL.
