# Object Cache and Unwrapped Cache

The KMS server uses two in-memory caches backed by
[`moka::future::Cache`](https://docs.rs/moka/latest/moka/future/struct.Cache.html),
a lock-free concurrent hash map. Both caches use sharding so multiple
Actix-web worker threads can read simultaneously without serialization.

---

## Architecture overview

```mermaid
graph TD
    CALLER[Caller]

    CALLER -->|retrieve_object| DB[Database]
    CALLER -->|get_unwrapped| GU[get_unwrapped]

    DB -->|get| OC[ObjectCache]
    OC -->|miss| BS[(Backing Store<br/>SQLite / Postgres)]

    GU -->|peek| UC[UnwrappedCache]
    UC -->|miss| CRYPTO[unwrap_object<br/>KEK unwrap]

    OC -->|stores| OC_VAL["wrapped ObjectWithMetadata<br/>+ fingerprint"]
    UC -->|stores| UC_VAL["unwrapped key material<br/>+ fingerprint of wrapped"]

    style BS fill:#f9f,stroke:#333
    style CRYPTO fill:#f99,stroke:#333
    style OC fill:#9f9,stroke:#333
    style UC fill:#9f9,stroke:#333
```

| Cache | Key | Value | Miss path |
|---|---|---|---|
| **ObjectCache** | UID string | `Arc<ObjectWithMetadata>` (wrapped) + fingerprint | DB fetch → insert → return |
| **UnwrappedCache** | UID string | unwrapped `Object` + fingerprint of wrapped | Crypto unwrap → insert → return |

---

## ObjectCache

**Source:** `crate/server_database/src/core/object_cache.rs`

Caches full `ObjectWithMetadata` as read from the database to eliminate repeated
DB round-trips on the hot path.

### Public API

| Method | Returns | Description |
|---|---|---|
| `get(uid)` | `Option<Arc<ObjectWithMetadata>>` | Lock-free lookup. Returns cheap `Arc` clone. |
| `insert(uid, owm)` | `DbResult<()>` | Store with fingerprint of `owm.object()`. |
| `insert_arc(uid, arc_owm)` | `DbResult<()>` | Store from existing `Arc` (saves one allocation). |
| `invalidate(uid)` | — | Remove entry. |
| `validate_cache(uid, current)` | `DbResult<()>` | Compare fingerprints; invalidate on mismatch. |

### Callers

- `Database::retrieve_object()` — `get()` on hot path, `insert()` on miss
- `Database::retrieve_object_arc()` — `get()`, `insert_arc()` on miss
- `Database::update_object()` — `invalidate()` on write
- `Database::validate_cache()` — `validate_cache()` after forced re-fetch

### Scenarios

#### S1 — Cold start (first access)

```mermaid
sequenceDiagram
    participant C as Caller
    participant DB as Database
    participant OC as ObjectCache
    participant BS as Backing Store

    C->>DB: retrieve_object("key-1")
    DB->>OC: get("key-1")
    OC-->>DB: None
    DB->>BS: retrieve("key-1")
    BS-->>DB: ObjectWithMetadata (wrapped)
    DB->>OC: insert("key-1", owm)
    DB-->>C: owm
```

#### S2 — Hot path (cache hit)

```mermaid
sequenceDiagram
    participant C as Caller
    participant DB as Database
    participant OC as ObjectCache

    C->>DB: retrieve_object("key-1")
    DB->>OC: get("key-1")
    OC-->>DB: cached entry found
    DB-->>C: owm via Arc unwrap_or_clone
```

#### S3 — retrieve_object_arc (zero-copy Arc path)

```mermaid
sequenceDiagram
    participant C as Caller
    participant DB as Database
    participant OC as ObjectCache
    participant BS as Backing Store

    C->>DB: retrieve_object_arc("key-1")
    DB->>OC: get("key-1")
    alt Cache hit
        OC-->>DB: cached Arc found
        DB-->>C: Arc clone (pointer bump)
    else Cache miss
        OC-->>DB: None
        DB->>BS: retrieve("key-1")
        BS-->>DB: owm
        DB->>OC: insert_arc("key-1", Arc.new(owm))
        DB-->>C: Arc
    end
```

#### S4 — Out-of-band mutation detected

```mermaid
sequenceDiagram
    participant DB as Database
    participant OC as ObjectCache

    Note over DB: Another process mutated "key-1"
    DB->>OC: validate_cache("key-1", current_db_object)
    OC->>OC: fingerprint(cached) != fingerprint(current)?
    OC->>OC: invalidate("key-1")
    Note over OC: Next get() triggers fresh DB fetch
```

#### S5 — Object update invalidates cache

```mermaid
sequenceDiagram
    participant C as Caller
    participant DB as Database
    participant OC as ObjectCache

    C->>DB: update_object("key-1", new_obj, new_attrs)
    DB->>OC: invalidate("key-1")
    DB->>DB: persist to backing store
    Note over OC: Entry removed, next get() is miss
```

#### S6 — Eviction (automatic)

moka eviction requires no explicit call:

| Policy | Trigger | Effect |
|---|---|---|
| LRU | `max_capacity` exceeded | Least-recently-used entry evicted |
| TTL | `time_to_idle` elapsed without access | Entry evicted |

---

## UnwrappedCache

**Source:** `crate/server_database/src/core/unwrapped_cache.rs`

Caches unwrapped key material to avoid repeated KEK-unwrap cryptographic operations.
The fingerprint of the **wrapped** object is stored alongside the unwrapped payload
so stale entries (after key re-wrapping or KEK rotation) are silently rejected.

### Public API

| Method | Returns | Description |
|---|---|---|
| `peek(uid, wrapped)` | `DbResult<Option<Object>>` | Returns unwrapped object if fingerprint matches. |
| `insert(uid, wrapped, unwrapped)` | `DbResult<()>` | Stores unwrapped with wrapped fingerprint. |
| `clear_cache(uid)` | — | Removes entry. |
| `validate_cache(uid, object)` | `DbResult<()>` | Fingerprint check; invalidate on mismatch. |

**Security guard:** `insert` returns `Err` if `wrapped == unwrapped` (defense-in-depth
against plaintext-persistence bugs).

### Callers

- `KMS::get_unwrapped()` — `peek()` + `insert()` on miss
- KMIP ReKey / ReKeyKeyPair — `clear_cache()` after rotation
- `Database::validate_cache()` chain — `validate_cache()` for defense-in-depth

### Scenarios

#### U1 — First unwrap (cold)

```mermaid
sequenceDiagram
    participant G as get_unwrapped()
    participant UC as UnwrappedCache
    participant CR as Crypto

    G->>UC: peek("key-1", wrapped_obj)
    UC-->>G: None (no entry)
    G->>CR: unwrap_object(wrapped_obj)
    Note over CR: KEK unwrap
    CR-->>G: unwrapped Object
    G->>UC: insert("key-1", wrapped_obj, unwrapped_obj)
    Note over UC: Stores fingerprint(wrapped) + unwrapped
    G-->>G: return unwrapped
```

#### U2 — Subsequent unwrap (hot, zero crypto)

```mermaid
sequenceDiagram
    participant G as get_unwrapped()
    participant UC as UnwrappedCache

    G->>UC: peek("key-1", wrapped_obj)
    UC->>UC: fingerprint matches?
    UC-->>G: Some(unwrapped_obj)
    Note over G: No cryptographic operation
    G-->>G: return unwrapped
```

#### U3 — Key re-wrapped (KEK rotation)

```mermaid
sequenceDiagram
    participant G as get_unwrapped()
    participant UC as UnwrappedCache
    participant CR as Crypto

    Note over G: wrapped_obj changed (new KEK after rotation)
    G->>UC: peek("key-1", new_wrapped_obj)
    UC->>UC: fingerprint mismatch
    UC-->>G: None (stale entry rejected)
    G->>CR: unwrap_object(new_wrapped_obj)
    CR-->>G: unwrapped Object
    G->>UC: insert("key-1", new_wrapped_obj, unwrapped)
    Note over UC: New fingerprint replaces old entry
    G-->>G: return unwrapped
```

#### U4 — Security guard (wrapped == unwrapped)

```mermaid
sequenceDiagram
    participant G as get_unwrapped()
    participant UC as UnwrappedCache

    Note over G: Bug: caller passes already-unwrapped object
    G->>UC: insert("key-1", obj, obj)
    UC->>UC: wrapped == unwrapped?
    UC-->>G: Err("wrapped and unwrapped objects should be different")
    Note over UC: Prevents plaintext-persistence bugs
```

#### U5 — Explicit invalidation on key rotation

```mermaid
sequenceDiagram
    participant R as ReKey / Rekeyer
    participant UC as UnwrappedCache

    R->>UC: clear_cache("key-1")
    Note over UC: Entry removed
    Note over UC: Next get_unwrapped() triggers crypto unwrap
```

#### U6 — Concurrent workers (double-unwrap acceptable)

```mermaid
sequenceDiagram
    participant W1 as Worker 1
    participant W2 as Worker 2
    participant UC as UnwrappedCache
    participant CR as Crypto

    W1->>UC: peek("key-1", wrapped)
    UC-->>W1: None (cold)
    W2->>UC: peek("key-1", wrapped)
    UC-->>W2: None (W1 has not inserted yet)

    W1->>CR: unwrap_object(...)
    CR-->>W1: unwrapped
    W1->>UC: insert("key-1", wrapped, unwrapped)

    Note over W2: Received None, must also unwrap
    W2->>CR: unwrap_object(...)
    CR-->>W2: unwrapped
    W2->>UC: insert("key-1", wrapped, unwrapped)
    Note over UC: Double unwrap on cold start is acceptable
```

---

## End-to-end: JOSE decrypt

Full trace of `POST /v1/crypto/decrypt` with `alg: RSA-OAEP`. The RSA wrapping
key (persistent DB object, identified by `kid`) passes through both caches.
The CEK (ephemeral, from the JWE `encrypted_key` field) is never cached.

```mermaid
sequenceDiagram
    participant J as JOSE /decrypt
    participant RF as retrieve_object_for_operation
    participant DB as Database
    participant OC as ObjectCache
    participant GU as get_unwrapped()
    participant UC as UnwrappedCache
    participant CR as Crypto
    participant OS as OpenSSL

    J->>RF: retrieve_object_for_operation(kid, Decrypt)
    RF->>DB: retrieve_objects(kid)

    alt ObjectCache hit
        DB->>OC: get(kid)
        OC-->>DB: cached (wrapped)
    else ObjectCache miss
        DB->>OC: get(kid)
        OC-->>DB: None
        DB->>DB: fetch from SQLite or Postgres
        DB->>OC: insert(kid, owm)
    end

    DB-->>RF: owm (wrapped)

    RF->>GU: get_unwrapped(kid, wrapped_obj, user)

    alt UnwrappedCache hit
        GU->>UC: peek(kid, wrapped_obj)
        UC-->>GU: Some(unwrapped_obj)
        Note over GU: No crypto
    else UnwrappedCache miss
        GU->>UC: peek(kid, wrapped_obj)
        UC-->>GU: None
        GU->>CR: unwrap_object(wrapped_obj)
        Note over CR: KEK unwrap
        CR-->>GU: unwrapped Object
        GU->>UC: insert(kid, wrapped_obj, unwrapped_obj)
    end

    GU-->>RF: unwrapped Object
    RF->>RF: owm.set_object(unwrapped)
    RF-->>J: owm with plaintext key

    J->>OS: kmip_private_key_to_openssl(owm.object())
    OS-->>J: OpenSSL PKey Private

    J->>OS: RSA private decrypt(encrypted_key)
    OS-->>J: CEK (Content Encryption Key)

    J->>OS: AES-GCM decrypt(ciphertext, CEK)
    OS-->>J: plaintext

    Note over J: CEK dropped here (ephemeral, not cached)
```

---

## Per-scenario cache behavior

| Scenario | ObjectCache | UnwrappedCache | DB round-trip | Crypto unwrap |
|---|---|---|---|---|
| 1st access, cold | miss → DB → insert | miss → crypto → insert | ✓ | ✓ |
| 2nd access, hot | hit | hit | — | — |
| Key re-wrapped (new KEK) | hit (wrapped) | miss → crypto → insert | — | ✓ |
| Cache evicted (TTL / LRU) | miss → DB → insert | miss → crypto → insert | ✓ | ✓ |
| Object updated in DB | invalidated → miss → DB | still valid (fingerprint unchanged) | ✓ | — |
| KEK rotated (Rekey) | invalidated | `clear_cache()` called explicitly | ✓ | ✓ (next access) |

---

## Configuration

Both caches are configured via the [server configuration file](server_configuration_file.md)
or CLI flags:

| Parameter | Default | Description |
|---|---|---|
| `object_cache_max_size` | Varies | Max entries in ObjectCache before LRU eviction |
| `object_cache_max_age` | Varies | Time-to-idle before eviction (seconds) |
| `unwrapped_cache_max_size` | 1000 | Max entries in UnwrappedCache (see CLI `--unwrapped-cache-max-size`) |

---

## Security considerations

1. **ObjectCache never stores plaintext keys.** It mirrors the database:
   objects are stored as-retrieved (wrapped). All callers provide the DB state.

2. **UnwrappedCache validates against wrapped fingerprint.** `peek()` compares
   the caller's `wrapped_object` fingerprint against the stored fingerprint.
   If the wrapped object changed (re-wrapped, corrupted), the entry is silently
   rejected.

3. **Security guard rejects `wrapped == unwrapped`.** `insert()` returns an
   error if the caller passes an already-unwrapped object as the wrapped argument.
   This is defense-in-depth against plaintext-persistence bugs.

4. **UnwrappedCache does NOT participate in persistence.** Unlike ObjectCache
   (checked by `retrieve_object` before every DB read), UnwrappedCache is only
   consulted by `get_unwrapped()`. Objects from UnwrappedCache are consumed
   in-memory for cryptographic operations and never written back to the database.

5. **Concurrent cold-start double-unwrap is acceptable.** If two workers call
   `get_unwrapped()` simultaneously for a cold key, both perform the cryptographic
   unwrap. The second `insert()` overwrites the first. This wastes one unwrap but
   avoids lock contention — a tradeoff favoring throughput.
