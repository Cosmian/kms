# Cosmian KMS Server Database

This crate implements the database layer that handles persistent storage of cryptographic objects, metadata, access control information, and logs. It supports multiple database backends and provides a unified interface for all storage operations.

## Supported Database Backends

- **SQLite**: Development and single-node deployments (`--database-type sqlite`)
- **PostgreSQL**: Production deployments with replication (`--database-type postgresql`)
- **MySQL/MariaDB**: Production deployments (`--database-type mysql`)
- **Redis (with Findex)**: Encrypted searchable storage (`--database-type redis-findex`, **not available in FIPS mode**)

## Database Schema

### SQL Databases (SQLite, PostgreSQL, MySQL)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                         KMS Database Schema                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ parameters                                                      │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │ name  VARCHAR(128) PRIMARY KEY                                  │    │
│  │ value VARCHAR(256)                                              │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ objects                                                         │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │ id         VARCHAR(128) PRIMARY KEY  -- Object UID              │    │
│  │ object     VARCHAR/LONGTEXT          -- Serialized KMIP object  │    │
│  │ attributes JSON                      -- KMIP attributes         │    │
│  │ state      VARCHAR(32)               -- Object state            │    │
│  │ owner      VARCHAR(255)              -- Owner user ID           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ read_access                                                     │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │ id          VARCHAR(128)             -- Object UID (FK)         │    │
│  │ userid      VARCHAR(255)             -- User ID                 │    │
│  │ permissions JSON                     -- Array of operations     │    │
│  │ UNIQUE (id, userid)                                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ tags                                                            │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │ id  VARCHAR(128)                     -- Object UID (FK)         │    │
│  │ tag VARCHAR(255)                     -- Tag value               │    │
│  │ UNIQUE (id, tag)                                                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Redis with Findex

The schema below use the following legend :

- ENC_KMS(...) = Data encrypted with KMS
- ENC_Findex(...) = Data encrypted with Findex
- permission_triplet = Tuple(user_id, obj_uid, permission)
- metadata = Object owner, tags, and other attributes

```text
KEY → VALUE
─────────────────────────────────────────────────────────────────────────
db_version                  → >= 5.12.0
db_state                    → "ready" | "upgrading"

do::<object_uid>            → ENC_KMS(object data)

ENC_Findex v8(o:obj_uid)    → ENC_Findex v8(permission_triplet)
ENC_Findex v8(u:userid)     → ENC_Findex v8(permission_triplet)
ENC_Findex v8(object_uid)   → ENC_Findex v8(metadata)
```

A more colorful and clear description of how the Redis backend operates with Findex can be red on the its original PR description : [github.com/Cosmian/kms/pull/542](https://github.com/Cosmian/kms/pull/542).

### Environment Variables

- `KMS_POSTGRES_URL`: PostgreSQL connection string
- `KMS_MYSQL_URL`: MySQL/MariaDB connection string
- `KMS_SQLITE_PATH`: SQLite database file path
- `KMS_REDIS_URL`: Redis connection string for Findex

### Connection Examples

```bash
# PostgreSQL
KMS_POSTGRES_URL=postgresql://user:password@host:5432/database

# MySQL
KMS_MYSQL_URL=mysql://user:password@host:3306/database

# SQLite
KMS_SQLITE_PATH=/path/to/database.db

# Redis (for Findex)
KMS_REDIS_URL=redis://host:6379
```

## Security

- **Encryption**: All sensitive data is encrypted before storage
- **Access Control**: Database-level and application-level security
- **Logging**: Complete audit trail of all operations

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
