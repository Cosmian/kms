# `cosmian_kms_interfaces` — Plugin & Store Abstractions

This crate defines the **trait boundaries** between the KMS server core and every
pluggable backend: SQL/Redis databases, HSMs, and software crypto oracles.

Nothing in this crate performs I/O; it only declares types and async trait
signatures that other crates must implement.

---

## Module map

```text
cosmian_kms_interfaces
├── stores/
│   ├── ObjectsStore        — CRUD + search for KMIP objects
│   ├── PermissionsStore    — grant / revoke / query access rights
│   ├── NotificationsStore  — create / list / mark-read rotation notifications
│   └── ObjectWithMetadata  — thin wrapper: Object + owner + State + Attributes
├── hsm/
│   ├── HSM                 — raw PKCS#11-level interface (create, encrypt, sign …)
│   └── HsmBackend          — ObjectsStore + CryptoOracle adapter backed by an HSM
└── CryptoOracle            — software/HSM encryption, decryption, signing by key prefix
```

---

## Trait overview

### Store traits

```mermaid
classDiagram
    class ObjectsStore {
        <<trait>>
        +create(uid, owner, object, attrs, tags)
        +retrieve(uid) ObjectWithMetadata
        +retrieve_tags(uid) HashSet~String~
        +update_object(uid, object, attrs, tags)
        +update_state(uid, state)
        +delete(uid)
        +atomic(ops Vec~AtomicOperation~)
        +is_object_owned_by(uid, owner) bool
        +find(requestor, state, attrs) Vec~ObjectWithMetadata~
        +find_wrapped_by(wrapping_key_uid, user)
        +find_due_for_rotation(now) Vec~String~
    }

    class PermissionsStore {
        <<trait>>
        +list_user_operations_granted(user)
        +list_object_operations_granted(uid)
        +grant_operations(uid, user, ops)
        +remove_operations(uid, user, ops)
        +list_user_operations_on_object(uid, user)
    }

    class NotificationsStore {
        <<trait>>
        +create_notification(user, event_type, msg, object_id, ts)
        +list_notifications(user, limit, offset)
        +count_unread(user) i64
        +mark_read(id, user, now)
        +mark_all_read(user, now)
    }

    class ObjectWithMetadata {
        +id() str
        +object() Object
        +owner() str
        +state() State
        +attributes() Attributes
    }

    ObjectsStore --> ObjectWithMetadata : returns
```

### HSM & crypto-oracle traits

```mermaid
classDiagram
    class HSM {
        <<trait>>
        +get_available_slot_list() Vec~usize~
        +get_supported_algorithms(slot_id)
        +create_key(slot_id, algo, len, sensitive)
        +create_keypair(slot_id, algo, key_len)
        +export(slot_id, object_id) HsmObject
        +delete(slot_id, object_id)
        +find(slot_id, filter) Vec~HsmObject~
        +encrypt(slot_id, key_id, data, params)
        +decrypt(slot_id, key_id, data, params)
        +sign(slot_id, key_id, data, algo)
        +generate_random(slot_id, len)
    }

    class HsmProvider {
        <<trait>>
        +low-level PKCS11 calls
    }

    class BaseHsmP {
        +impl HSM for BaseHsm~P~
        where P: HsmProvider
    }

    class CryptoOracle {
        <<trait>>
        +encrypt(uid, data, params) EncryptedContent
        +decrypt(uid, data, params) Zeroizing~Vec~u8~~
        +get_key_type(uid) KeyType
        +get_key_metadata(uid) KeyMetadata
        +sign(uid, data, algo)
    }

    class HsmBackend {
        +Arc~dyn HSM~
        +Clone
        +impl ObjectsStore for HsmBackend
        +impl CryptoOracle for HsmBackend
    }

    HSM <|.. BaseHsmP : implements
    HsmProvider <|.. BaseHsmP : bounds P
    BaseHsmP --> HsmBackend : wrapped in Arc
    HsmBackend ..|> ObjectsStore : implements
    HsmBackend ..|> CryptoOracle : implements
```

---

## Global overview — who implements and who consumes

The diagram reads left-to-right: *implementors* on the left drive through the
*trait layer* (centre) into the *consumers* on the right.

```mermaid
flowchart LR
    subgraph impl_db["SQL / KV backends<br/>(server_database)"]
        SQ["SQLite · PostgreSQL<br/>MySQL / MariaDB"]
        RD["Redis + Findex"]
        NOOP["NoopNotificationsStore"]
    end

    subgraph impl_hsm["HSM chain"]
        PROV["5 × HsmProvider<br/>(pkcs11 loader crates)"]
        BH["BaseHsm&lt;P&gt;"]
        HB["HsmBackend"]
    end

    subgraph traits["cosmian_kms_interfaces"]
        OS[ObjectsStore]
        PS[PermissionsStore]
        NS[NotificationsStore]
        CO[CryptoOracle]
        HSMt[HSM]
    end

    subgraph consumers["cosmian_kms_server"]
        DB["Database struct"]
        KMS["KMS struct"]
    end

    SQ   -->|"OS + PS + NS"| OS & PS & NS
    RD   -->|"OS + PS"| OS & PS
    NOOP -->|"NS"| NS

    PROV -->|"impl HsmProvider"| BH
    BH   -->|"impl HSM"| HSMt
    HSMt -->|"Arc&lt;dyn HSM&gt;"| HB
    HB   -->|"impl OS"| OS
    HB   -->|"impl CO"| CO

    OS   -->|"Arc&lt;dyn&gt;"| DB
    PS   -->|"Arc&lt;dyn&gt;"| DB
    NS   -->|"Arc&lt;dyn&gt;"| DB
    DB   -->|field| KMS
    CO   -->|"Box&lt;dyn&gt;"| KMS
    HSMt -->|"Option&lt;Arc&lt;dyn&gt;&gt;"| KMS
```

---

## Store backends

All SQL engines implement the three store traits. Redis implements only the two
persistence traits; `NoopNotificationsStore` fills the notifications gap.

```mermaid
flowchart LR
    subgraph backends["cosmian_kms_server_database"]
        SQ_S[SqlitePool]
        SQ_P[PgPool]
        SQ_M["MySqlPool / MariaDB"]
        RD[RedisWithFindex]
        NOOP[NoopNotificationsStore]
    end

    OS[ObjectsStore]
    PS[PermissionsStore]
    NS[NotificationsStore]

    SQ_S & SQ_P & SQ_M -->|impl| OS & PS & NS
    RD                  -->|impl| OS & PS
    NOOP                -->|impl| NS
```

---

## HSM chain

Five provider crates each implement `HsmProvider`. `BaseHsm<P>` uses that bound
to satisfy `HSM`. A single `HsmBackend` wraps the resulting `Arc<dyn HSM>` and
is `Clone`d to fill both the object-store map and the crypto-oracle map in
`KMS::instantiate()`.

```mermaid
flowchart LR
    subgraph providers["PKCS#11 loader crates"]
        SFT[softhsm2]
        UTI[utimaco]
        PRT[proteccio]
        C2P[crypt2pay]
        SCH[smartcard-hsm]
    end

    subgraph base["cosmian_kms_base_hsm"]
        BH["BaseHsm&lt;P: HsmProvider&gt;"]
    end

    subgraph iface["cosmian_kms_interfaces"]
        HSMt["HSM trait"]
        HB["HsmBackend (Clone)"]
        OS[ObjectsStore]
        CO[CryptoOracle]
    end

    SFT & UTI & PRT & C2P & SCH -->|"impl HsmProvider"| BH
    BH  -->|"impl HSM"| HSMt
    HSMt -->|"Arc&lt;dyn HSM&gt;"| HB
    HB  -->|"impl"| OS
    HB  -->|"impl"| CO
```

---

## Request flow — ReKey using store abstractions

The sequence below shows how the `ReKey` operation uses each store trait during
symmetric key rotation (including wrapping-key rewrap).

```mermaid
sequenceDiagram
    participant Client as HTTP Client
    participant Route as actix-web route
    participant Op as rekey.rs
    participant KMS as KMS struct
    participant DB as dyn ObjectsStore
    participant CO as dyn CryptoOracle

    Client->>Route: POST /kmip/2_1 (ReKey)
    Route->>Op: rekey(kms, request, owner)
    Op->>KMS: database.retrieve_object(uid)
    KMS->>DB: retrieve(uid)
    DB-->>Op: ObjectWithMetadata

    alt key is itself wrapped
        Op->>KMS: unwrap_object(object, kms, owner)
        KMS->>CO: decrypt(wrapping_key_uid, ciphertext, params)
        CO-->>Op: plaintext key bytes
    end

    Op->>Op: generate fresh key material
    Op->>KMS: database.find_wrapped_by(old_uid, owner)
    KMS->>DB: find_wrapped_by(old_uid, owner)
    DB-->>Op: Vec of wrapped dependants

    loop for each wrapped dependant
        Op->>KMS: unwrap then re-wrap with new key
        KMS->>CO: decrypt / encrypt
    end

    Op->>KMS: database.atomic([Create(new), UpdateObject(old), ...])
    KMS->>DB: atomic(ops)
    DB-->>Op: Ok

    Op-->>Route: ReKeyResponse { new_uid }
    Route-->>Client: 200 OK (TTLV)
```

---

## Key types

| Type | Source file | Description |
|---|---|---|
| `ObjectWithMetadata` | `stores/object_with_metadata.rs` | KMIP `Object` + owner + `State` + `Attributes` |
| `AtomicOperation` | `stores/objects_store.rs` | `Create`, `Upsert`, `UpdateObject`, `UpdateState`, `Delete` |
| `Notification` | `stores/notifications_store.rs` | Rotation/renewal event record with read status |
| `HsmObject` | `hsm/interface.rs` | Raw key material exported from an HSM slot |
| `KeyMetadata` | `crypto_oracle.rs` | Algorithm, length, sensitivity, and ID of a key |
| `EncryptedContent` | `crypto_oracle.rs` | Ciphertext + optional IV / authentication tag |
| `InterfaceError` | `error/mod.rs` | Unified error type for all interface operations |

---

## Adding a new backend

1. Add a crate dependency on `cosmian_kms_interfaces`.
2. Implement `ObjectsStore` and `PermissionsStore` (required for SQL/KV stores).
3. Optionally implement `NotificationsStore` (or use `NoopNotificationsStore`).
4. For HSM backends: implement `HsmProvider` in a new `*_pkcs11_loader` crate;
   `BaseHsm<YourProvider>` then automatically satisfies `HSM`, and `HsmBackend::new()
   becomes usable as both`ObjectsStore` and `CryptoOracle` without further code.
5. Register the backend in `cosmian_kms_server_database` (SQL) or
   `KMS::instantiate()` (HSM / crypto oracle).
