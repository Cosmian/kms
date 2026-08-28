# Oral Script — Eviden KMS (16 slides)

> **Usage**: this file is the oral presentation script. Each section gives the substance to
> deliver, not the slide description. Passages in **bold** are the key points to hammer home.
> Target duration: ~2 min per slide, ~32 min total.

---

## Slide 1 — Title

Welcome. We are going to talk about Eviden KMS — a key management system that is part of
Eviden's cybersecurity portfolio, the entity that emerged from Atos's security division.

**This is not just another KMS.** Eviden KMS was designed from the ground up to address three
needs simultaneously: manage keys, serve as a cryptographic oracle at scale, and act as a
certificate authority (PKI) — including post-quantum.

It is written entirely in Rust, a memory-safe language that eliminates by design a whole class
of attacks (buffer overflow, use-after-free). This is an intrinsic security argument, not a
marketing one.

The source code is available on GitHub under the BSL 1.1 licence: any security team can audit
it. And it is **100% developed in the European Union**, which matters for public procurement
and NIS2 compliance.

---

## Slide 2 — What is Eviden KMS?

Let us start with what this product actually does, because "KMS" covers very different realities
depending on the vendor.

**First role: key lifecycle manager.** Every key — symmetric AES, asymmetric RSA/EC key pair,
X.509 certificate — is created, activated, revoked and destroyed within the KMS. The KMIP
lifecycle (Pre-Active → Active → Deactivated → Destroyed) ensures that a key cannot be used
outside its authorisation window.

**Second role: interoperability hub.** KMIP 1.0 to 2.1 in binary and JSON, cloud-native
integrations (AWS XKS, Azure EKM/DKE, Google CSE/CMEK), and transparent database encryption
(Oracle, PostgreSQL/EDB/IRIS, MongoDB, MySQL via TDE or CSFLE). Whatever your ecosystem —
Synology, FortiGate, VMware, AWS, Azure, GCP — there is a native connector. A single KMS
instance covers all providers, all protocols, all databases.

**Third role: HSM gateway.** All application keys are wrapped by master keys that never leave
the hardware — Proteccio, Crypt2Pay, Utimaco, Nitrokey. At runtime, the KMS unwraps on demand
via PKCS#11; the HSM is never exposed directly to applications.

The official documentation is available at docs.cosmian.com. The transport protocol is KMIP in
binary on port 5696, or JSON on port 9998 via REST — which simplifies integration into existing
architectures.

---

## Slide 3 — Why Eviden KMS?

Other KMS products exist on the market. Here is why this one stands out.

**Performance first.** Rust provides a real advantage: no garbage collector, zero unnecessary
copies during serialisation, non-blocking async model. The KMS can parallelise operations
across all available cores and handle thousands of concurrent requests without degrading latency.
This is critical for use cases where the KMS sits in the critical path of every application
request.

**FIPS 140-3 compliance by default.** This is not an option you enable after the fact. It is
the default compilation mode. The OpenSSL FIPS provider is loaded at startup via a `OnceLock`
to guarantee atomic initialisation. For non-FIPS environments (post-quantum algorithms, FPE,
ChaCha20), compile with `--features non-fips`.

**Interoperability.** KMIP 1.0 to 2.1 in binary and JSON, native PKCS#11 module, WASM client,
OpenAPI 3.1 with Swagger UI. Whatever your ecosystem — Oracle, MongoDB, Synology, FortiGate —
there is a connector.

**HSM-first architecture.** Application keys are wrapped by master keys that never leave the
HSM. At runtime, the KMS unwraps on demand, absorbs concurrent load, and the HSM is never
exposed directly.

---

## Slide 4 — System architecture

This diagram shows the complete path of a KMIP request from the network down to cryptographic
primitives.

**The entry point**: HTTP/TLS on Actix-web, the most performant Rust framework on the market.
TTLV deserialisation (the KMIP binary format) is done with zero copy. A dispatcher maps the
KMIP tag to the corresponding Rust function.

**The core**: the `KMS` struct concentrates three resources — the database, cryptographic
oracles, and HSM connections. This is deliberately stateless: no per-session state, no global
lock. Each node can process any request.

**The database**: SQLite for development, PostgreSQL or MySQL/Percona in production,
Redis-findex for fully-indexed encryption in non-FIPS mode. The database stores encrypted
(wrapped) keys, never in plaintext.

**Crypto primitives**: the `cosmian_kms_crypto` crate builds OpenSSL 3.6.2 from source at
compile time, with a verified SHA-256. No dependency on a system OpenSSL that could be
compromised or misconfigured.

**HSMs**: connection via standardised PKCS#11. The KMS loads the vendor module (Utimaco,
Proteccio, Nitrokey…) at startup and uses it to wrap/unwrap master keys.

---

## Slide 5 — Supported algorithms

Two worlds coexist in Eviden KMS.

**The FIPS world** is what you deploy by default in production. AES-GCM is the workhorse:
128, 192 or 256 bits, a 12-byte random nonce, a 16-byte authentication tag. Perfect for the
vast majority of use cases. AES-XTS is reserved for disk encryption (fixed-size sectors). Key
wrapping follows RFC 3394 (AES-KW) and RFC 5649 (AES-KWP with padding), both recommended by
NIST SP 800-38F.

**The post-quantum world** is accessible in non-FIPS mode. Three families from the NIST 2024
standards:

- **ML-KEM** (FIPS 203): key encapsulation. Replaces ECDH in session-establishment protocols.
- **ML-DSA** (FIPS 204): signatures. Replaces ECDSA and RSA for long-lived certificates and
  JWTs.
- **SLH-DSA** (FIPS 205): stateless, hash-based signatures. Very conservative; useful for
  signing artefacts with a very long lifetime (10–30 years).

**The hybrid strategy** is recommended during the transition: ML-KEM-768 + X25519 combines the
quantum security of ML-KEM with the proven security of X25519. If one is broken, the other
still protects.

---

## Slide 6 — KMIP protocol support

KMIP is the OASIS standard for interoperability between KMS and applications. Its goal is to
eliminate redundant proprietary integrations: a single protocol for Oracle, MongoDB, Synology,
VMware, FortiGate, and so on.

**Eviden KMS supports all KMIP versions from 1.0 to 2.1.** In practice, this means you can
connect a Synology DSM (KMIP 1.2) and a Snowflake (KMIP 2.1) to the same KMS with no special
configuration. The server automatically detects the client version.

**The Baseline Server profile is fully compliant**: the 9 mandatory operations (Create,
Register, Get, Locate, Destroy, Activate, Revoke, Query, Discover Versions) plus the 18
recommended optional operations — everything is implemented.

**Two encodings are available:**

- Binary TTLV on port 5696 (TLS, client certificate authentication) — for maximum performance
  and industrial clients.
- JSON on port 9998 via REST — for developers, testing, and lightweight integrations. The
  Swagger UI at `/swagger-ui` allows interactive API exploration.

All internal communications use KMIP 2.1: the server translates on the fly to the version
requested by the client. This guarantees longevity: you can migrate to KMIP 2.1 incrementally,
client by client.

---

## Slide 7 — Key lifecycle

The KMIP lifecycle is the backbone of key governance. Understanding this diagram means
understanding how Eviden KMS enforces security policies.

**Pre-Active**: the key exists in the database (encrypted), but no cryptographic operation is
allowed. Useful for preparing a rotation: you create the new key before switching, with no risk
of premature use.

**Active**: all operations are permitted. This is the normal production state.

**Deactivated**: you can still decrypt data encrypted with this key (for backwards
compatibility), but you can no longer use it to encrypt new data. This is the intermediate
rotation state: the new key is Active, the old one is Deactivated.

**Compromised**: the key is considered potentially exposed. You can still attempt to decrypt
data for forensic analysis, but no new operation is permitted. This is an emergency state that
normally triggers an incident response procedure.

**Destroyed**: the key material is zeroed. The identifier is retained in the database for the
audit trail — you can know that a key existed and when it was destroyed, without knowing its
content.

Access control is granular: each object has an owner, and permissions (read, use, manage) can
be delegated by user or by group. Multi-tenancy is enforced at the database level: one tenant
can never see another tenant's objects.

---

## Slide 8 — Cloud integrations

Here is the question every CISO asks: *if my data is in the cloud, who really controls the
keys?*

There are several answer models, and Eviden KMS implements them all.

**The live proxy model (XKS, EKM, CSE, DKE)** is the strongest. The key NEVER leaves the KMS
perimeter. AWS, Google or Microsoft must call your KMS for every encryption or decryption
operation. If you cut access to the KMS, data in the cloud immediately becomes inaccessible —
even to the cloud provider.

**The BYOK model** is weaker: you generate the key in your KMS, import it into the cloud, and
the cloud keeps a copy. You control the generation process, but you have no guarantee that your
key is not being used without your knowledge.

**The power of XKS and EKM** lies in their universality: a single KMS integration automatically
covers all compatible AWS or GCP services. You enable XKS once, and S3, EBS, RDS, DynamoDB,
Secrets Manager — everything goes through your KMS with no additional per-service configuration.

For digital sovereignty and strict regulatory compliance (critical NIS2, classified defence,
health data), the live proxy model is the only viable option.

---

## Slide 9 — AWS XKS and Azure DKE

Let us take a deeper look at two particularly important integrations.

**AWS XKS**: when an AWS service needs to encrypt or decrypt data, AWS KMS receives the request
and delegates it to your Eviden KMS via the XKS Proxy API. AWS KMS acts as a relay — it cannot
do anything without a response from your KMS. The encryption key never resides in AWS
infrastructure. Practical consequence: a US court order (subpoena) targeting AWS cannot compel
disclosure of your data, since AWS does not hold the keys.

**Azure DKE (Double Key Encryption)** works differently. Microsoft 365 encrypts documents with
two keys: a Microsoft key (stored in Azure Key Vault) and your Eviden KMS key. To decrypt,
BOTH keys are required. This is true dual control: neither Microsoft alone nor you alone can
decrypt a document. This is particularly suited to ultra-sensitive data — intellectual property,
executive data, legal documents under NDA.

An important point: DKE is only available in Microsoft 365 E5 licences or advanced compliance
add-ons. It is an enterprise feature, not a consumer one.

---

## Slide 10 — Database integrations

Protecting data at the source — directly within databases — is an increasingly common
requirement from regulations (PCI-DSS level 1, HIPAA, GDPR article 32).

**Transparent Data Encryption (TDE)** is the most common mechanism. The database encrypts its
data files using a key stored in an external KMS. If someone steals the disk or the backup,
the data is unreadable without access to the KMS.

**The Oracle integration** uses the Eviden KMS PKCS#11 module. Oracle TDE calls the module as
a software HSM. The Oracle TDE Master Key is wrapped and stored in Eviden KMS, never in
plaintext in the Oracle wallet.

**MongoDB CSFLE (Client-Side Field Level Encryption)** goes further: encryption is performed
on the application side before sending data to MongoDB. Eviden KMS provides keys via KMIP 1.0.
Even the MongoDB administrator cannot read the encrypted fields — including queryable fields
thanks to Queryable Encryption.

**EDB Postgres Advanced Server TDE** (versions 15.2+ and 17.x) integrates via KMIP 2.1 over
mTLS. EDB uses a bundled Python script (`edb_tde_kmip_client.py`) invoked through the
`PGDATAKEYWRAPCMD` and `PGDATAKEYUNWRAPCMD` variables. At `initdb`, Postgres generates a random
DEK, sends it to the KMS via KMIP Encrypt (AES-256-CBC), and stores the wrapped DEK. At each
startup, the KMS unwraps the DEK on demand. The integration works in **non-FIPS** mode (the
PyKMIP library used by EDB uses `ssl.wrap_socket`, which is not FIPS-certified).

**InterSystems IRIS** supports database encryption via KMIP 2.0 over mTLS. IRIS connects to
Eviden KMS on port 5696 to create, retrieve and manage symmetric keys used to encrypt database
files on disk. Configuration on the IRIS side is done via `^SECURITY` (IRIS security manager)
or `^EncryptionKey`. As with EDB, this integration works in **non-FIPS** mode.

**Separation of duties** is the major architectural benefit: DBAs administer data, security
teams administer keys in the KMS. These two perimeters are completely isolated, which compliance
auditors particularly appreciate.

---

## Slide 11 — Storage and disk encryption

Encryption use cases are not limited to databases. The Eviden KMS PKCS#11 module opens access
to a much broader ecosystem.

**VeraCrypt and LUKS** use the PKCS#11 module to store their volume encryption keys in the KMS
rather than on the disk itself. The key is never present locally — the volume can only be
mounted if the KMS is accessible. This is decentralised access control applied to disk
encryption.

**VMware vCenter** with the Trust Key Provider (KMIP 1.1) allows VMDKs (virtual machine disks)
to be encrypted with keys managed by the KMS. In the event of a physical seizure of a
hypervisor, the VMs are unreadable without access to the KMS.

**Veeam Backup** encrypts its backups with KMIP 1.4 keys stored in Eviden KMS. This is
critical: an unencrypted backup is often the most neglected data leak vector. With this
integration, a stolen backup is useless without the KMS.

**FortiGate** connects to the KMS via KMIP to manage encryption keys used for VPN tunnels and
firewall rule encryption. This is an example of integration with a physical network appliance —
the KMS is not reserved for cloud architectures.

---

## Slide 12 — HSM support

Hardware Security Modules (HSMs) provide the highest hardware security guarantee for keys.
Eviden KMS integrates them in a way that preserves their benefits while working around their
main limitation: performance.

**The problem with standalone HSMs**: a mid-range HSM performs 2,000 to 10,000 RSA operations
per second. For an application handling thousands of concurrent requests, the HSM becomes a
catastrophic bottleneck.

**The solution**: the KMS stores encrypted (wrapped) application keys in its database. At
startup or on first access, the KMS decrypts each application key by asking the HSM to unwrap
the master key. The application key is then in the KMS RAM, available for the thousands of
subsequent requests — without going back to the HSM.

**Result**: the security of the HSM "at creation" and "at rest", the performance of the KMS
"at execution". The best of both worlds, explicitly documented in the Eviden architecture.

The supported HSMs cover the main vendors in the European market: Trustway Proteccio and
Crypt2Pay (Atos/Eviden group), Utimaco, Nitrokey HSM 2 / SmartCard-HSM. SoftHSM2 is available
for development environments and CI/CD testing.

---

## Slide 13 — Public Key Infrastructure (PKI)

Eviden KMS is a complete PKI. This is not a secondary feature — it is a first-class use case
documented in detail in the official documentation.

**What this means in practice:** you can use Eviden KMS to replace a PKI based on OpenSSL +
scripts, or as an internal enterprise PKI, with a web interface, a KMIP API, and certificate
management integrated with key management.

**Post-quantum certificates** are the major differentiating point. Eviden KMS is one of the
few KMS products to natively implement the IETF RFCs for PQC certificates:

- RFC 9881 for ML-DSA in X.509 (FIPS 204)
- RFC 9909 for SLH-DSA in X.509 (FIPS 205)
- RFC 9935 for ML-KEM in X.509 (FIPS 203)

**Cross-algorithm PKI** allows you to build hybrid certification chains: a root RSA 4096 CA can
issue ML-DSA-44 certificates for post-quantum leaf nodes. Or conversely, an ML-DSA CA can issue
RSA certificates for backwards compatibility. This is exactly the migration scenario recommended
by NIST.

**Note on the ML-KEM case**: ML-KEM is a key encapsulation mechanism (KEM), not a signature.
An ML-KEM certificate cannot be self-signed — it must always be issued by a signing CA (RSA,
EC, ML-DSA). The KMS enforces this constraint automatically.

---

## Slide 14 — Anonymisation and format-preserving encryption

This feature addresses a specific need: how to use sensitive data for analysis, testing or
development, without exposing the real values?

**Format-Preserving Encryption (FPE FF1)** is the answer for structured data. A 16-digit
payment card number is encrypted into another 16-digit number. The structure is preserved, the
SQL column type remains `VARCHAR(16)`, and application queries work identically. This is a
migration to encryption that requires no schema changes.

**Hashing** (SHA-2, SHA-3, Argon2) is for one-way identifiers: you store the hash of a social
security number to perform joins without ever storing the real number. Argon2 is specifically
designed to resist dictionary attacks on low-entropy values.

**Differential noise** (Laplace, Gaussian) is the recommended technique for publishing
statistics on sensitive data. A calibrated noise is added that preserves the statistical
distribution but makes it impossible to reconstruct individual values. This is the foundation
of *differential privacy*, used by Apple, Google and the US Census Bureau.

**Tokenisation** replaces a value with an opaque token. Unlike encryption, the token has no
mathematical relationship with the original value — an attacker who obtains the token learns
nothing, even if they know the algorithm.

---

## Slide 15 — High availability

Eviden KMS is designed to be stateless. This is the fundamental architectural choice that makes
high availability trivial to operate.

**Why stateless?** Because the state (keys, attributes, access policies) is in the shared
database. A KMS node can be restarted, replaced, or added at any time with no coordination
between nodes. There is no leader election, no session synchronisation, no sticky sessions at
the load balancer.

**The reference architecture** uses HAProxy in TCP passthrough mode (TLS is decrypted by the
KMS nodes, not by the load balancer — which preserves end-to-end mTLS authentication) and
Keepalived for the VRRP VIP between two load balancers.

**Failover times** are important to know for SLAs:

- Loss of a KMS node: ~9 seconds (HAProxy health check cycle)
- Loss of the active load balancer: ~2 seconds (VRRP fails the VIP over)
- Adding a new node: 0 seconds client-side (just add the node to the HAProxy config; clients
  see nothing)

**The database is the only shared state.** It is therefore the only critical point in high
availability. Operational recommendations are clear: PostgreSQL in primary/replica mode with
streaming replication, or a managed cloud solution (RDS, Cloud SQL, Azure Database for
PostgreSQL). Regular backups and restoration tests are mandatory.

---

## Slide 16 — Getting started with Eviden KMS

Let us close with action: how to go from this presentation to a first test in under five
minutes?

**Docker is the fastest path.** A single command launches a fully operational KMS in SQLite
mode, with the web interface immediately accessible at `http://localhost:9998/ui`. This is
sufficient to explore features, test integrations, and write the first KMIP calls.

**For production**, Debian/RPM packages are available at `package.cosmian.com/kms/` for
on-premise deployments. Marketplace images are available on AWS, Azure and GCP for cloud
deployments — pre-configured with the correct network security policies.

**The `ckms` CLI** is the Swiss Army knife of Eviden KMS. It covers all operations: key
management, encryption, decryption, PKI, anonymisation, access management. It can be installed
via `cargo install ckms` or downloaded directly from the website.

**The Swagger API** at `/swagger-ui` is the best entry point for developers: it lets you
explore and test all KMIP operations directly in the browser, without writing a single line of
code.

To go further: `docs.cosmian.com/key_management_system/` contains the full documentation,
per-product integration guides, and tutorials. The source code at `github.com/Cosmian/kms`
allows you to open issues, follow the roadmap and contribute.
