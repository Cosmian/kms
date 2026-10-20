## Testing

### Multi-region active-active PostgreSQL guards

- Added `mise run test:multi-region-guards` (`.mise/tasks/test/multi-region-guards`,
  backed by `.mise/lib/multi_region_guards.sh`) — a guard suite that validates the
  multi-region active-active PostgreSQL deployment model end to end:
  - **CRL issuance gating** — the live pgEdge proof checks that a follower region rejects
    CRL generation with a clear leader-region error, the leader's CRL replicates to the
    follower's `crls` table, a follower-side revocation does not silently regenerate the
    leader's CRL, and a leader regeneration converges on the replicated revocation.
  - **Ceremony activation gating** — the live pgEdge proof checks that a follower rejects
    Crypto Officer ceremony activation and revocation, leader activations/revocations
    replicate, and a mismatched `ceremony_secret` against replicated records fails secure
    (`not a CO`, not an error).
  - **Object-state conflict merge** — the live pgEdge proof races `Destroyed` against
    `Deactivated` in both commit orderings and asserts both regions converge to the
    most-restrictive state; a static source guard additionally pins the
    `ENABLE ALWAYS` trigger and its `GREATEST(state)` guard function in `pgsql.rs`.
  - **Grants/permissions** — the live pgEdge proof races a grant against a revoke on the
    same object/user and asserts both regions converge to one identical permission set
    (documented last-write-wins limitation).
  - **Schema / replication invariants** — live SQL guards verify the real
    `PRIMARY KEY`s (`tags_pkey`, `read_access_pkey`, `crypto_officer_activations_pkey`)
    with `REPLICA IDENTITY DEFAULT` and the Spock node/subscription wiring on both nodes.
  - **Operator-config guards** — when given node configs via `--configs`, the task detects
    multi-region misconfigurations: more than one (or zero) `leader` regions, a non-PostgreSQL
    backend (`sqlite`/`mysql`/`redis-findex`), `clear_database = true` on any node,
    mismatched `ceremony_secret`/`ceremony_key_id` across ceremony-enabled regions, HSM slots
    (HSM-stored objects do not replicate), and auto-rotation cron enabled on more than one
    region (rotation is not leader-gated). When no configs are given, a self-test proves the
    detectors fire on synthetic configurations.
- Wired the guard suite into the CI matrix (`.github/workflows/test_all.yml`) as a
  non-FIPS-only job to avoid duplicating the pgEdge behavioral-test runtime.
