## Features

### Multi-node cluster support: scheduled-job locks, heartbeats, richer `/health` (#1366)

- Scheduled jobs (auto-rotation, CRL refresh, metrics reconciliation) now take a PostgreSQL advisory lock or a
  MySQL/MariaDB named lock, so a job runs on one node at a time. SQLite is single-node and Redis-with-Findex is not
  coordinated yet.
- Each node writes a heartbeat to a new `cluster_nodes` table (created automatically) and a leader is elected for
  display. A node is considered gone after 15 seconds without heartbeat. The leader does not gate any work, so a
  failover never interrupts service.
- New authenticated `GET /cluster/status` lists live nodes, versions, last heartbeat and the leader, and a new
  `kms.cluster.nodes` metric reports the node count.
- `GET /health` now reports per-dependency latency and the status of each configured HSM. A failing HSM reports
  `DEGRADED` (HTTP 200) while a failing database still reports `DOWN` (HTTP 503). The HSM check reflects the PKCS#11
  library's answer: some libraries (e.g. Crypt2pay) do not report an unreachable device.
