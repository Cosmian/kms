## Features

### Database

- Wire the Redis-with-Findex backend into the version-sequenced startup migration runner (`Migrate`), with a 30-minute lease lock (`kms_db_migration_lock` via `SET ... NX PX 1800000` and Lua compare-and-delete release), resumption of interrupted `upgrading` runs, refusal of pre-`5.12.0` (Findex v5 / unversioned) databases, and released `5.20.0`/`5.24.0`/`5.28.0` Redis migration fixtures ([#1270](https://github.com/Cosmian/kms/issues/1270), [#1272](https://github.com/Cosmian/kms/issues/1272)).
