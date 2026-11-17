---
name: kms-db-compat
description: 'Check a diff that changes SQL or Redis-with-Findex storage, or persisted KMIP serde types, for upgrade, downgrade (N-1), round-trip and mixed-version safety; emit a per-change verdict table and run the SQLite upgrade/downgrade proof. Use when a change touches crate/server_database, *.sql files or persisted KMIP types, or when asked about upgrade/downgrade compatibility.'
---

# KMS DB Compat

Normative rules: `.github/instructions/database-compatibility.instructions.md` (sync rule 4.18). This skill is the workflow; report-only unless invoked in self-review.

## Step 1 — Collect storage changes

Base ref: the argument, default `origin/develop`, falling back to `HEAD~1` (as in `/kms-sync-rules` Step 1).

```bash
BASE="${1:-origin/develop}"
# merge-base form (no `...`): includes uncommitted tracked changes, so it works in self-review before commit
git diff "$(git merge-base "$BASE" HEAD)" -- crate/server_database crate/kmip/src/kmip_0/kmip_types.rs crate/kmip/src/kmip_2_1/kmip_attributes.rs crate/kmip/src/kmip_2_1/kmip_objects.rs crate/kmip/src/kmip_2_1/kmip_types.rs
git status --short | grep '^??' | grep -E 'crate/(server_database|kmip)'   # untracked new files are not in the diff
```

List from the diff:

- every changed `-- name:` entry in `*.sql`;
- every new `CREATE`, `ALTER`, `DROP` and `clean-table-*`;
- every new Redis key format string or prefix (`format!("…::{uid}")`, `MATCH` patterns);
- every enum variant, `#[serde(...)]` or field change in the KMIP files;
- every new `parameters` marker constant in `stores/migrate.rs`.

List empty → output `No storage change` and stop.

## Step 2 — Classify

Map each item to a row number of the instruction file's classification table. For KMIP items, confirm the type is reachable from `Object`/`Attributes`:

```bash
grep -n "<Type>" crate/kmip/src/kmip_2_1/kmip_attributes.rs crate/kmip/src/kmip_2_1/kmip_objects.rs
```

Not reachable → mark `not persisted` and drop it.

## Step 3 — Answer the four directions per item

One sentence with `file:line` evidence per direction:

- **Upgrade**: is there an idempotent startup step in every backend?
- **Downgrade**: do N-1's startup and queries still work? Read N-1 source with `git show <prev-tag>:<path>`, where `prev-tag=$(git tag --sort=-v:refname -l '[0-9]*.[0-9]*.[0-9]*' | head -1)`.
- **Round-trip**: is there a startup reconcile, or only a marker?
- **Mixed version**: is anything unsafe while both versions run?

## Step 4 — Verdict and missing actions

Output this table inline; write no file:

`| Change (file:line) | Row | Upgrade | Downgrade N-1 | Round-trip | Mixed | Verdict | Missing action |`

- Any `BREAKING` row ends with `needs user approval (N-1 policy)`.
- A missing `**Downgrade.**` doc paragraph, missing reconcile or missing re-instantiate test goes in `Missing action`, citing the instruction file's "Required in the same change" section.

## Step 5 — Proof (SQLite)

Run when any item is not `SAFE`, or any item is in rows 2, 4-7 or 11. The four `cosmian_kms` and `ckms` binaries must share the same FIPS/non-FIPS mode.

```bash
PREV=$(git tag --sort=-v:refname -l '[0-9]*.[0-9]*.[0-9]*' | head -1)
git worktree add "../kms-$PREV" "$PREV"
cargo build --manifest-path "../kms-$PREV/Cargo.toml" -p cosmian_kms_server -p ckms
cargo build -p cosmian_kms_server -p ckms
# upgrade: previous release -> this branch
mise run test:db:upgrade-sqlite --old-kms "../kms-$PREV/target/debug/cosmian_kms" --old-ckms "../kms-$PREV/target/debug/ckms" --new-kms target/debug/cosmian_kms --ckms target/debug/ckms
# downgrade: this branch seeds, previous release opens the copy
mise run test:db:upgrade-sqlite --old-kms target/debug/cosmian_kms --old-ckms target/debug/ckms --new-kms "../kms-$PREV/target/debug/cosmian_kms" --ckms "../kms-$PREV/target/debug/ckms"
git worktree remove "../kms-$PREV"
```

- Report the exit status of each run.
- A downgrade failure on an item already rated DEGRADED is expected, and must match the documented gap.
- PostgreSQL, MySQL: the evidence is `cargo test -p cosmian_kms_server_database -- --ignored --exact tests::test_db_<postgresql|mysql>` with the re-instantiate test.
- Redis: `cargo test -p cosmian_kms_server_database --features non-fips -- --ignored --exact tests::test_db_redis_with_findex`. The test is `#[cfg(feature = "non-fips")]`: without the feature it matches 0 tests and still exits 0. For every backend, require `1 passed` in the output; `0 passed` is not a proof.
- Containers: the `docker run` lines in `.github/instructions/rust-database.instructions.md` § Testing and the comments in `crate/server_database/src/tests/mod.rs`.

## Worked example

`gcm_invocations` (rows 1, 7, 11):

- Upgrade: `CREATE TABLE IF NOT EXISTS` at startup.
- Round-trip: reconciled by the startup purge (`purge-orphan-gcm-invocations`, `purge_orphan_gcm_invocations`), tested by `gcm_invocations_orphan_purge_test`.
- Downgrade: encryptions N-1 performs are not counted, so DEGRADED, documented in the `**Downgrade.**` paragraph of `tables.md`.
