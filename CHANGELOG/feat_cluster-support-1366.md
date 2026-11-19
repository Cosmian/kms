## Features

### Multi-node cluster support: scheduled-job locks, heartbeats, richer `/health` ([#1366](https://github.com/Cosmian/kms/issues/1366))

- Scheduled jobs (auto-rotation, CRL refresh, metrics reconciliation, KV secret TTL expiry) now take a PostgreSQL advisory lock or a
  MySQL/MariaDB named lock, so a job runs on one node at a time. SQLite is single-node and Redis-with-Findex is not
  coordinated yet. Percona XtraDB Cluster refuses named locks in its default strict mode: the server then logs one
  warning and runs the jobs on every node, as before.
- Each node writes a heartbeat to a new `cluster_nodes` table (created automatically) and a leader is elected for
  display. A node is considered gone after 15 seconds without heartbeat. The leader does not gate any work, so a
  failover never interrupts service.
- New authenticated `GET /cluster/status` lists live nodes, versions, last heartbeat and the leader, and a new
  `kms.cluster.nodes` metric reports the node count.
- `GET /health` now reports per-dependency latency and the status of each configured HSM. A failing HSM reports
  `DEGRADED` (HTTP 200) while a failing database still reports `DOWN` (HTTP 503). The HSM check reflects the PKCS#11
  library's answer: some libraries (e.g. Crypt2pay) do not report an unreachable device. Each HSM slot is probed with a
  2 second limit and at most one probe per slot at a time, so an HSM that stops answering makes the node `DEGRADED`
  without hanging `/health` or exhausting the server's threads. The database check has the same 2 second limit: a
  database that stops answering now gives `DOWN` (HTTP 503) instead of a request that never returns.

## Bug Fixes

### Database

- MySQL/MariaDB: several nodes starting at the same time on a fresh database no longer fail with
  `Duplicate key name 'idx_objects_owner'` (or a duplicate column): a column or index created by another node
  between the existence check and the `ALTER`/`CREATE INDEX` is now accepted.

## Documentation

- Add the [Cluster coordination](documentation/docs/installation/cluster_coordination.md) page ([#1366](https://github.com/Cosmian/kms/issues/1366)), with Mermaid
  diagrams of the job locks and the heartbeat, and the `/health` and `/cluster/status` responses.
- Rework the high-availability documentation ([#1366](https://github.com/Cosmian/kms/issues/1366)): the
  [High availability and deployment profiles](documentation/docs/installation/high_availability_mode.md) page compares
  the ways to run the KMS (single node or Cosmian confidential VM, cloud load balancer, round-robin DNS, Keepalived
  without HAProxy with a tested configuration, HAProxy), with the limits of each and Mermaid diagrams. The HAProxy and
  Keepalived setup has its own page, [HAProxy and Keepalived](documentation/docs/installation/haproxy_keepalived.md).

---

Closes #1366
