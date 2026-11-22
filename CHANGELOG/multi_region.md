## Features

### Multi-region active-active: region role

- Add the `region_role` setting (`--region-role`, `KMS_REGION_ROLE`): `leader` (default) or `follower`. Exactly one
  region of a multi-region deployment is the leader. A `follower` requires PostgreSQL with logical multi-master
  replication or a MySQL Galera cluster; on SQLite or Redis-with-Findex it is rejected at startup.
- CRL generation and Crypto Officer ceremony activation and revocation run on the leader region only: a follower
  answers them with HTTP 422 and an error naming the leader-only restriction.

### Multi-region active-active PostgreSQL: scheduled jobs and cluster tables

- The scheduled jobs of the cluster coordination (#1366) lock in the node's own database, and each region has its own:
  the lock cannot exclude a job running in another region. Key auto-rotation and renewal warnings now run on the
  leader region only (`region_role = "leader"`); a follower skips them, as it already skips the CRL refresh.
- Operator wiring of the replication set: `cluster_nodes` (node heartbeats and display leader) stays out of the
  replication set, and `gcm_invocations.count` is merged by Spock delta-apply, so the AES-GCM invocation counts of the
  regions add up instead of overwriting each other. See
  [Multi-region active-active deployment](../documentation/docs/configuration/database/multi_region.md).
- Lifecycle events and their tombstones advance the object's version, so conditional writes reject snapshots taken before a state transition, including transitions applied through replication.
- Initialize the KV/SSH internal identifier key on the leader before serving; followers only read its replicated value and return a retry error while it is missing, preventing conflicting per-region keys and unreachable metadata.

### Multi-region active-active MySQL (Galera)

- A `region_role = "follower"` now runs on a MySQL Galera cluster (Percona XtraDB Cluster validated; MariaDB Galera and
  MySQL Group Replication multi-primary expected to work). A follower on SQLite or Redis-with-Findex is rejected at
  startup.
- MySQL lifecycle writes are monotonic: `update_state` joins the stored state with the new one (`Destroyed` and
  `Compromised` never regress, `Destroyed_Compromised` is kept), an explicit downgrade (batch Undo) writes the state, and
  a payload update no longer brings key material back on a `Destroyed` object. These guards apply to every MySQL
  deployment, like the PostgreSQL event log.
- Scheduled jobs on Galera: when the server refuses `GET_LOCK` (Percona XtraDB Cluster strict mode, MariaDB Galera),
  the job lock is a row of the new `kms_cron_locks` table instead of running the job on every node (or on none).
  See [Multi-region active-active deployment](../documentation/docs/configuration/database/multi_region.md#mysql-with-galera).

### Configuration wizard: deployment-profile decision tree

- `cosmian_kms configure` now starts with the questions of the
  [high-availability guide](../documentation/docs/installation/high_availability_mode.md#choosing-a-profile) and derives
  the deployment profile. The profile restricts the database choice (SQLite is offered for a single node only,
  PostgreSQL or MySQL (Galera) for multi-region), writes `region_role` for the multi-region profile, skips the
  "clear database" prompt when several nodes or regions share the data, defaults the HTTP and KMIP socket hosts to
  `0.0.0.0` for multi-node profiles, and prints the profile's operating notes at the end.

### Database

- PostgreSQL, every deployment (single- and multi-region): at startup the server gives `tags` and `read_access` a
  primary key, adds an identity primary key column `id` to `crypto_officer_activations`, and creates the insert-only
  lifecycle event tables `object_state_events` and `object_state_event_tombstones` with the triggers that derive
  `objects.state` from them.
- Downgrade, PostgreSQL (DEGRADED), every PostgreSQL deployment, not only multi-region: a rolling restart from the
  previous release is not supported. Once this release has recorded its version an older KMS refuses to start, and
  until then an older node's Activate, Revoke or Destroy has no effect on objects that have lifecycle events. Stop
  every older node before starting the first node of this release. The lifecycle event log is now reconciled with
  `objects` at every startup (event-less objects get a baseline event, events of deleted objects are purged),
  replacing the one-time `object_state_events_backfilled` marker.

## Testing

### Multi-region active-active PostgreSQL guards

- Added `mise run test:db:multi-region-guards` (`.mise/tasks/test/db/multi-region-guards`,
  backed by `.mise/lib/multi_region_guards.sh`) — a guard suite that validates the
  multi-region active-active PostgreSQL deployment model end to end:
  - **CRL issuance gating** — the live pgEdge proof checks that a follower region rejects
    CRL generation with a clear leader-region error, the leader's CRL replicates to the
    follower's `crls` table, a follower-side revocation does not regenerate the leader's CRL
    itself, and the leader's CRL refresh job publishes the replicated revocation.
  - **Ceremony activation gating** — the live pgEdge proof checks that a follower rejects
    Crypto Officer ceremony activation and revocation, leader activations/revocations
    replicate, and a mismatched `ceremony_secret` against replicated records fails secure
    (`not a CO`, not an error).
  - **Object-state conflict merge** — object lifecycle state is an insert-only replicated
    event log (`object_state_events`, `object_state_event_tombstones`) folded into
    `objects.state` by `ENABLE ALWAYS` triggers, because Spock `last_update_wins` drops older
    rows before triggers run. The live pgEdge proof partitions replication deterministically
    and asserts convergence for `Destroyed` vs `Deactivated` in both orders,
    `Compromised` + `Destroyed` = `Destroyed_Compromised`, no key material resurrected on a
    Destroyed row, and replicated batch-UNDO downgrades; live SQL guards verify the installed triggers on both nodes.
  - **Grants/permissions** — the live pgEdge proof races a grant against a revoke on the
    same object/user and asserts both regions converge to one identical permission set
    (documented last-write-wins limitation).
  - **Schema / replication invariants** — live SQL guards verify the real
    `PRIMARY KEY`s (`tags_pkey`, `read_access_pkey`, `crypto_officer_activations_pkey`, `object_state_events_pkey`,
    `object_state_event_tombstones_pkey`)
    with `REPLICA IDENTITY DEFAULT` and the Spock node/subscription wiring on both nodes.
  - **Operator-config guards** — when given node configs via `--configs`, the task detects
    multi-region misconfigurations: more than one (or zero) `leader` regions, a backend other than
    PostgreSQL or MySQL (`sqlite`/`redis-findex`) or mixed backends across regions, `clear_database = true` on any node,
    mismatched `ceremony_secret`/`ceremony_key_id` across ceremony-enabled regions, HSM slots
    (HSM-stored objects do not replicate), and auto-rotation cron enabled on followers only
    (followers skip it, so no region would rotate). When no configs are given, a self-test proves the
    detectors fire on synthetic configurations.
- Wired the guard suite into the CI matrix (`.github/workflows/test-db.yml`) as a
  non-FIPS-only job to avoid duplicating the pgEdge behavioral-test runtime.
