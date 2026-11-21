# High availability and deployment profiles

KMS nodes are stateless: all data lives in the database. They can be scaled horizontally from a single node up to any
number of nodes, simply by connecting them all to the same database and putting a single entry point in front of them.
A deployment is therefore two choices: **which database**, and **how clients reach the nodes**. This page lists the
usual profiles, from the simplest to the most available, and what each one gives and does not give. To serve clients
from several regions, each with its own database, see [Profile 6](#profile-6-multi-region-active-active).

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart LR
    classDef client fill:#e1d5e7,stroke:#9673a6,stroke-width:2px,color:#000
    classDef entry fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#000
    classDef kms fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000
    classDef db fill:#ffe6cc,stroke:#d79b00,stroke-width:2px,color:#000

    clients["💻 Clients<br/>(KMIP / HTTPS)"]:::client
    entry["🔀 Single entry point<br/>(load balancer,<br/>VIP or DNS name)"]:::entry

    subgraph kms_cluster["🛡️ KMS nodes (stateless)"]
        node1["Eviden KMS<br/>Node 1"]:::kms
        node2["Eviden KMS<br/>Node 2"]:::kms
        nodeN["Eviden KMS<br/>Node n"]:::kms
    end

    db[("🗄️ Shared database<br/>PostgreSQL,<br/>MySQL or MariaDB")]:::db

    clients --> entry
    entry --> node1 & node2 & nodeN
    node1 & node2 & nodeN -->|"database connection"| db
```

The connection from the nodes to PostgreSQL and MySQL/MariaDB can be secured with TLS: see
[Securing database connections](../configuration/database/configuration.md#securing-database-connections-with-tls--mtls).

How the nodes share background jobs and report their state (`/health`, `/cluster/status`) is described in
[Cluster coordination](./cluster_coordination.md).

## Choosing a profile

| # | Profile | Nodes | Clients reach the KMS through | When a node fails | Typical use |
| - | ------- | ----- | ----------------------------- | ----------------- | ----------- |
| 1 | [Single node](#profile-1-single-node) | 1 | the address of the node | the service stops | development, tests, small sites, a Cosmian confidential VM |
| 2 | [Cloud load balancer](#profile-2-cloud-load-balancer) | 2+ | a managed load balancer | the balancer stops sending requests to it | cloud |
| 3 | [Round-robin DNS](#profile-3-round-robin-dns) | 2+ | a DNS name with one record per node | nothing automatic: requests keep going to it until it leaves the DNS | simple load spreading |
| 4 | [Keepalived only](#profile-4-keepalived-only) | 2+ | a virtual IP (VIP) shared by the nodes | the VIP moves to another node in a few seconds | on premises, nodes on one network |
| 5 | [HAProxy, with or without Keepalived](#profile-5-haproxy) | 2+, plus 1 or 2+ load balancers | one HAProxy, or a VIP over several HAProxy | HAProxy stops sending requests to it | on premises, load spread over all nodes |
| 6 | [Multi-region active-active](#profile-6-multi-region-active-active) | 1+ per region, in two regions | the nearest region (geo DNS or a global load balancer), each region with profile 2 to 5 inside | the other region keeps serving; clients of the failed region move to it | local reads and writes in two regions, with asynchronous convergence |

Profiles 2 to 5 need a PostgreSQL or MySQL/MariaDB database shared by all the nodes (see
[Rules common to profiles 2 to 5](#rules-common-to-profiles-2-to-5)). The availability of the database itself is a
separate choice, described in [Database availability](#database-availability). Profile 6 repeats one of them in each
region, with a PostgreSQL database per region.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TD
    classDef question fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#000
    classDef profile fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000

    vm{"Run the KMS in a<br/>Cosmian<br/>confidential VM?"}:::question
    start{"More than one<br/>KMS node?"}:::question
    where{"Where do the<br/>nodes run?"}:::question
    spread{"Spread the load<br/>over all nodes?"}:::question

    p1["Profile 1<br/>Single node"]:::profile
    p2["Profile 2<br/>Cloud load balancer"]:::profile
    p3["Profile 3<br/>Round-robin DNS"]:::profile
    p4["Profile 4<br/>Keepalived only"]:::profile
    p5["Profile 5<br/>HAProxy (+ Keepalived)"]:::profile
    p6["Profile 6<br/>Multi-region active-active"]:::profile
    regions{"Serve clients from<br/>several regions?"}:::question

    vm -->|yes: one VM| p1
    vm -->|no| regions
    regions -->|"yes, one database<br/>per region"| p6
    regions -->|no| start
    start -->|no| p1
    start -->|yes| where
    where -->|cloud, managed<br/>load balancer| p2
    where -->|no load balancer,<br/>no failover needed| p3
    where -->|on premises| spread
    spread -->|no, failover is enough| p4
    spread -->|yes| p5
```

`cosmian_kms configure` asks these questions first, then restricts the database choice to the profile,
writes `region_role` for profile 6 and prints the profile's operating notes.

## Rules common to profiles 2 to 5

- All the nodes use the **same database**: PostgreSQL or MySQL/MariaDB. SQLite supports one node only. Several nodes
  on Redis with Findex are not supported for now: its scheduled jobs are not coordinated (see
  [Cluster coordination](./cluster_coordination.md#supported-databases)).
- All the nodes expose the **same server certificate**, and its name is the name clients use: the DNS name of the load
  balancer, of the VIP, or of the DNS record.
- The nodes must listen on an address reachable from the clients. The HTTPS server listens on `0.0.0.0` by default (on
  Linux and macOS). The KMIP socket server listens on `127.0.0.1` by default: set `socket_server_hostname` to
  `0.0.0.0` if clients use KMIP on port 5696.

!!! warning "File-based audit logging is not multi-instance safe"
    If audit logging is enabled (`--audit-enable`), each KMS node must write to its **own**
    audit file, not a shared/network volume. The file backend uses a local lock to serialize
    writes; it only prevents corruption on a single node (e.g. during a rolling restart), not
    across nodes. Pointing several replicas at the same audit file means only one of them will
    ever actually write to it — the others sit idle, so you silently lose their events.
    A centrally consolidated, multi-writer-safe audit trail requires the
    [PostgreSQL audit backend](../configuration/audit-postgresql-backend.md) instead.

### What the nodes share

Because the KMS nodes are stateless, the **shared database is the source of truth**: ensure you have **regular database backups**
(and periodically test restores) using your database engine's recommended procedures.
In-memory object caches validate lifecycle state and security-sensitive attributes against the shared database using a short bounded revalidation interval (2 seconds by default). This preserves hot-path cache performance while bounding cross-node propagation lag when keys are revoked, deactivated, or destroyed on any node.

### What `/health` tells a load balancer

Every profile except the first uses `GET /health` on the HTTP(S) port (`9998` by default) to decide whether a node is usable:

| Situation on the node | `GET /health` | `GET /health?strict=true` | Effect |
| --------------------- | ------------- | ------------------------- | ------ |
| The database is down, or silent for more than 2 seconds | `503` (`DOWN`) | `503` | the node leaves the pool |
| An HSM does not answer | `200` (`DEGRADED`) | `503` | with `strict=true` the node leaves the pool; without, it stays and the requests that need the HSM fail on it |
| The KMIP socket server has stopped, the HTTPS server answers | `200` (`DEGRADED`) | `503` | same as above, for KMIP clients |

Use `?strict=true` when a node that cannot serve all its requests must not receive any. The body of the answer is the same
in both cases. See [Cluster coordination](./cluster_coordination.md#get-health) for the details.

## Profile 1: single node

One KMS and one database, SQLite included. Clients connect to the address of the node. There is no failover: restore
the node or its database from a backup. See [Getting started](./installation_getting_started.md).

In a **Cosmian confidential VM**, the KMS runs in one VM with its own encrypted Redis database (Redis with Findex): see
[Deploying in a Cosmian Confidential VM](./marketplace_guide.md). Several Cosmian VMs, each with the default Redis with
Findex database, are not supported for now.

## Profile 2: cloud load balancer

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    classDef client fill:#e1d5e7,stroke:#9673a6,stroke-width:2px,color:#000
    classDef lb fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#000
    classDef kms fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000
    classDef db fill:#ffe6cc,stroke:#d79b00,stroke-width:2px,color:#000

    clients["💻 Clients (KMIP / HTTPS)"]:::client
    lb["🔀 Cloud load balancer<br/>one address<br/>health check: /health"]:::lb
    node1["KMS node 1"]:::kms
    node2["KMS node 2"]:::kms
    nodeN["KMS node n"]:::kms
    db[("🗄️ Shared database")]:::db

    clients --> lb
    lb --> node1 & node2 & nodeN
    node1 & node2 & nodeN --> db
```

Use a managed load balancer of your cloud provider, in front of the nodes:

- forward the KMIP port (`5696`) and the HTTPS port (`9998`) as plain TCP, so that TLS ends on the nodes and every node
  presents the same certificate;
- check the nodes with `GET /health?strict=true` and keep a node in the pool only on `200`.

Adding or removing a node does not change the address clients use.

## Profile 3: round-robin DNS

Publish one DNS record per node under a single name, with a short TTL. Clients resolve the name and spread over the
nodes.

This profile has **no failover**: DNS does not know that a node is down. The failed node keeps receiving requests until
it is removed from the DNS and the TTL has expired, unless the client library tries the next address by itself, which
depends on the client. Use it for load spreading in a lab or when a failure of a node is acceptable, or add health
checks at the DNS provider.

## Profile 4: Keepalived only

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    classDef client fill:#e1d5e7,stroke:#9673a6,stroke-width:2px,color:#000
    classDef vip fill:#f8cecc,stroke:#b85450,stroke-width:2px,stroke-dasharray: 5 5,color:#000
    classDef kms fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000
    classDef idle fill:#f5f5f5,stroke:#999,stroke-width:2px,color:#000
    classDef db fill:#ffe6cc,stroke:#d79b00,stroke-width:2px,color:#000

    clients["💻 Clients (KMIP / HTTPS)"]:::client
    vip["🌐 Virtual IP (VIP)"]:::vip
    node1["Node 1 (MASTER)<br/>KMS + Keepalived"]:::kms
    node2["Node 2 (BACKUP)<br/>KMS + Keepalived"]:::idle
    db[("🗄️ Shared database")]:::db

    clients --> vip
    vip -.->|held by the MASTER| node1
    vip -.->|taken over<br/>if node 1 fails| node2
    node1 --> db
    node2 --> db
```

The Keepalived instances of the nodes talk to each other with VRRP to agree on which node holds the VIP.

Keepalived runs **on the KMS nodes themselves**, with no HAProxy. The nodes share a VIP: the MASTER node holds it and
answers the clients, the other nodes wait. Each Keepalived checks the KMS of its own node with
`GET /health?strict=true`; when the check fails, that node gives up the VIP and another node takes it.

Requirements:

- the nodes are on the same network (layer 2), and VRRP traffic (IP protocol 112) is allowed between them;
- Keepalived is installed on every node, and the VIP is free on that network;
- the KMS listens on all addresses (see [Rules common to profiles 2 to 5](#rules-common-to-profiles-2-to-5)), and the
  server certificate carries the DNS name of the VIP.

The same configuration is used on every node. Change only `priority` and the two unicast addresses on each node (the
highest `priority` starts as MASTER):

```keepalived
global_defs {
    enable_script_security
    script_user keepalived_script       # An unprivileged user, created beforehand
}

vrrp_script chk_kms {
    script "/usr/bin/curl -skf -m 2 -o /dev/null https://127.0.0.1:9998/health?strict=true"
    interval 2
    fall 2                              # 2 failed checks: the node leaves the VIP
    rise 2                              # 2 good checks: the node can hold the VIP again
}

vrrp_instance KMS {
    state BACKUP                        # BACKUP on every node: the priority decides
    interface eth0                      # Adapt to your network interface name
    virtual_router_id 51                # Identical on all nodes
    priority 101                        # 101 on node 1, 100 on node 2, ...
    advert_int 1
    unicast_src_ip 192.168.1.11         # Address of this node
    unicast_peer {
        192.168.1.12                    # Addresses of the other nodes
    }
    virtual_ipaddress {
        192.168.1.100/24                # VIP: the address clients use
    }
    track_script {
        chk_kms
    }
}
```

!!! note "Behaviour seen in a test"
    In a lab with two nodes and one PostgreSQL database, the VIP moved to the other node about 3 seconds after the KMS
    process of the MASTER stopped, and about 3 seconds after the MASTER lost its network. When the first node came
    back, it took the VIP again, without failed requests on a client that opens a new connection for each request. Add
    Keepalived's `nopreempt` option if you prefer that the VIP stays where it is.
    When the database stopped, `/health` stopped answering `200` on both nodes, both gave up the VIP, and the VIP came
    back by itself when the database was back.

Limits of this profile:

- **Active/passive**: only the node holding the VIP serves clients; the others are spare. To spread the load, use
  profile 2 or 5.
- An open KMIP connection is cut when the VIP moves: the client has to reconnect.
- The check follows what [`/health` tells a load balancer](#what-health-tells-a-load-balancer): the script above uses
  `?strict=true`, so a node whose HSM fails, or whose KMIP socket server has stopped, gives up the VIP.
- It does not work on AWS: in a test, an address added to an instance's network interface was not reachable from the
  other instances of the same subnet. Use profile 2 there. Other public clouds were not tested.

## Profile 5: HAProxy

HAProxy spreads the requests over all the nodes and stops sending requests to a node that fails its health check:

- **one HAProxy** in front of the nodes: load spreading and failover between nodes, but HAProxy is a single point of
  failure;
- **two or more HAProxy with Keepalived**: the same, with a VIP over the HAProxy nodes, so that no component is a single
  point of failure.

The configuration of both is described in [HAProxy and Keepalived](./haproxy_keepalived.md). Check the nodes with
`GET /health?strict=true` to also take out the nodes that `/health` reports as `DEGRADED` (see
[What `/health` tells a load balancer](#what-health-tells-a-load-balancer)).

## Profile 6: multi-region active-active

Each region runs its own group of KMS nodes and its own PostgreSQL node, and the PostgreSQL nodes replicate to one
another with a logical multi-master extension (validated with pgEdge Spock). Clients use the nearest region, which
serves reads and writes locally. Inside a region, use one of profiles 2 to 5 for the nodes.

```mermaid
%%{init: {"flowchart": {"curve": "linear"}}}%%
flowchart TB
    classDef client fill:#e1d5e7,stroke:#9673a6,stroke-width:2px,color:#000
    classDef entry fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#000
    classDef kms fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000
    classDef db fill:#ffe6cc,stroke:#d79b00,stroke-width:2px,color:#000

    clients["💻 Clients"]:::client
    geo["🌍 Geo DNS or global<br/>load balancer"]:::entry

    subgraph eu["EU — leader region"]
        lb_eu["🔀 Regional entry point<br/>(profile 2 to 5)"]:::entry
        kms_eu["🛡️ KMS nodes"]:::kms
        db_eu[("🗄️ PostgreSQL EU")]:::db
    end
    subgraph us["US — follower region"]
        lb_us["🔀 Regional entry point<br/>(profile 2 to 5)"]:::entry
        kms_us["🛡️ KMS nodes"]:::kms
        db_us[("🗄️ PostgreSQL US")]:::db
    end

    clients --> geo
    geo --> lb_eu & lb_us
    lb_eu --> kms_eu --> db_eu
    lb_us --> kms_us --> db_us
    db_eu <-.->|"logical multi-master<br/>replication"| db_us
```

What differs from profiles 2 to 5:

- **One database per region**, not one for all the nodes. The rules common to profiles 2 to 5 apply inside each region.
- **One `region_role = "leader"` region**, all the others `follower`. CRL generation, Crypto Officer ceremonies and
  background key auto-rotation run on the leader region only; a follower rejects the first two with an HTTP 422 (the
  client retries on the leader region) and skips the third. Everything else is served by every region.
- **Cluster coordination stays inside a region**: job locks, heartbeats, `GET /cluster/status` and
  `GET /health` describe the region that answers (see
  [Multi-region deployments](./cluster_coordination.md#multi-region-deployments)). Point the health check of each
  regional entry point at its own nodes, with `?strict=true` if a degraded node must leave the pool.
- **Convergence is eventual**: a change made in a region reaches the others after the replication lag. Object
  lifecycle states converge to the most restrictive one (a destroyed key stays destroyed in every region).
- The validated topology has **two regions**, and the database must be PostgreSQL. All the regions use the same
  `ceremony_secret`.

The topology, what converges and how, the replication set to configure and the limits are in
[Multi-region active-active deployment](../configuration/database/multi_region.md); the settings are in
[Database configuration](../configuration/database/configuration.md#multi-region-active-active-postgresql-spock--pgedge--bdr).

## Database availability

In profiles 1 to 5, all nodes depend on one database: if it is down, no node can serve requests. In profile 6, this dependency is local to each region; another region can continue serving against its own database. Make each database highly available with the tools of your database:

- PostgreSQL: streaming replication with an HA manager such as Patroni or pg_auto_failover, or a managed multi-zone
  service;
- MySQL / MariaDB: the replication or cluster solution of your platform.

Point `database_url` of all the nodes to the address that follows the primary (a VIP or the endpoint of the managed
service). The details and the constraints of each engine are in
[Database configuration](../configuration/database/configuration.md). Back up the database regularly and test the
restores: it is the source of truth of the whole cluster.
