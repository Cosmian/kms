---
name: rust-patterns
description: 'KMS-specific Rust design patterns: newtype wrappers, builder config, command pattern for KMIP ops, trait-based HSM/DB abstraction, key lifecycle state machine. Use as a reference for Rust patterns in this codebase.'
---

# Rust Design Patterns for the KMS Codebase

Reference for KMS-specific Rust patterns. Apply these when implementing new features or refactoring existing code.

## Pattern 1 — Newtype Wrappers for Identifiers

Prevent accidental parameter swaps between different string-typed IDs.

```rust
// ❌ Before: easy to swap uid and owner accidentally
async fn get_object(uid: String, owner: String, ...) -> KResult<KmipObject>

// ✅ After: compiler enforces correct parameter order
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UniqueIdentifier(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(pub String);

async fn get_object(uid: &UniqueIdentifier, owner: &UserId, ...) -> KResult<KmipObject>
```

Use newtypes for:

- `UniqueIdentifier` — KMIP object UIDs
- `UserId` — authenticated user identity
- `KeyId` — key identifiers in HSM contexts
- `GroupId` — access control group identifiers

## Pattern 2 — Builder Pattern for Server Configuration

Avoid large constructor argument lists. Use a builder when a config struct has more than 4 fields or optional fields.

```rust
// ❌ Before: unreadable 8-argument constructor
let config = ServerConfig::new(db_url, port, tls_cert, tls_key, fips_mode, auth_config, hsm_config, log_level);

// ✅ After: self-documenting builder
let config = ServerConfig::builder()
    .database_url(db_url)
    .port(9998)
    .tls(TlsConfig { cert: cert_path, key: key_path })
    .auth(auth_config)
    .build()?;  // .build() returns KResult<ServerConfig> for validation

// Builder implementation
pub struct ServerConfigBuilder { /* optional fields */ }

impl ServerConfigBuilder {
    pub fn database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = Some(url.into());
        self
    }

    pub fn build(self) -> KResult<ServerConfig> {
        Ok(ServerConfig {
            database_url: self.database_url.ok_or_else(|| kms_error!("database_url required"))?,
            // ...
        })
    }
}
```

## Pattern 3 — Command Pattern for KMIP Operations

Encapsulate each KMIP operation as a value to enable uniform dispatch, logging, and access control.

```rust
// A KMIP operation request as a typed value
pub struct GetOperation {
    pub unique_identifier: UniqueIdentifier,
    pub key_format_type: Option<KeyFormatType>,
}

// All operations implement a common trait
pub trait KmipOperation: Send + Sync {
    type Response;
    fn operation_type(&self) -> OperationType;
}

impl KmipOperation for GetOperation {
    type Response = GetResponse;
    fn operation_type(&self) -> OperationType { OperationType::Get }
}

// The dispatcher stays clean
pub async fn dispatch(op: Operation, kms: &KMS, params: &ExtraParams) -> KResult<Operation> {
    match op {
        Operation::Get(req) => get::execute(kms, req, params).await.map(Operation::GetResponse),
        Operation::Create(req) => create::execute(kms, req, params).await.map(Operation::CreateResponse),
        // ...
    }
}
```

## Pattern 4 — Trait-Based Abstraction for Database Backends

The `crate/interfaces/` crate defines database traits. Implement them rather than depending on concrete types.

```rust
// ✅ Depend on the trait, not a concrete DB type
pub async fn store_object(
    uid: &UniqueIdentifier,
    object: &KmipObject,
    db: &dyn ObjectsDb,  // trait object — works for SQLite, PostgreSQL, Redis
) -> KResult<()> {
    db.upsert(uid, object).await
}

// ❌ Avoid concrete type dependencies in operation handlers
pub async fn store_object(
    uid: &UniqueIdentifier,
    object: &KmipObject,
    db: &SqliteDb,  // wrong — breaks with other backends
) -> KResult<()>
```

Key traits in `crate/interfaces/`:

- `ObjectsDb` — KMIP object storage (CRUD)
- `PermissionsDb` — access control (grant/revoke/check)
- `Hsm` — HSM operations (sign, decrypt, generate key)

## Pattern 5 — State Machine for Key Lifecycle

KMIP key states are a well-defined state machine. Represent them as types, not strings.

```rust
// KMIP 2.1 §3.22 — State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    PreActive,
    Active,
    Deactivated,
    Compromised,
    Destroyed,
    DestroyedCompromised,
}

impl State {
    /// Returns true if the transition to `next` is permitted by KMIP spec.
    pub fn can_transition_to(self, next: State) -> bool {
        matches!(
            (self, next),
            (State::PreActive, State::Active)
            | (State::Active, State::Deactivated)
            | (State::Active, State::Compromised)
            | (State::Deactivated, State::Compromised)
            | (State::Deactivated, State::Destroyed)
            | (State::Compromised, State::Destroyed)
            | (State::Compromised, State::DestroyedCompromised)
        )
    }
}

// Use in Revoke / Destroy handlers
if !current_state.can_transition_to(target_state) {
    return Err(kms_error!("Invalid state transition: {:?} → {:?}", current_state, target_state));
}
```

## Pattern 6 — Macro for KMIP Error Construction

Avoid boilerplate in error creation across operation files:

```rust
// Use the project's existing error macro pattern
// Instead of:
return Err(KmsError::InvalidRequest(format!("Key {} not found", uid.0)));

// Use the macro defined in crate/server/src/:
return Err(kms_error!("Key {} not found", uid.0));
```

## Pattern 7 — Extension Traits for Cross-Cutting Concerns

Add methods to external types without modifying them:

```rust
// Add KMS-specific helpers to standard Result
pub trait KmsResultExt<T> {
    fn map_access_denied(self) -> KResult<T>;
}

impl<T> KmsResultExt<T> for Result<T, DbError> {
    fn map_access_denied(self) -> KResult<T> {
        self.map_err(|e| match e {
            DbError::NotFound => KmsError::Unauthorized("object not found or access denied".into()),
            other => KmsError::Database(other),
        })
    }
}

// Usage — consistent error mapping without repeating the match
let obj = db.get(&uid).await.map_access_denied()?;
```

## Pattern 8 — `macro_rules!` for Repetitive Match Dispatch

When multiple operations share identical boilerplate wiring:

```rust
macro_rules! impl_kmip_accessor {
    ($op:ident, $handler:path) => {
        Operation::$op(req) => {
            trace!("{} operation", stringify!($op));
            $handler(kms, req, params).await.map(Operation::$op)
        }
    };
}

// In dispatch.rs:
match operation {
    impl_kmip_accessor!(Get, get::execute),
    impl_kmip_accessor!(Create, create::execute),
    impl_kmip_accessor!(Locate, locate::execute),
    // ...
}
```

## Quick Rules

- Prefer **generics** over `dyn Trait` unless the set of types is open at runtime
- Keep all **`use` statements** at the top of the file — never inline inside function bodies
- Gate non-FIPS code at the **function/module level** with `#[cfg(feature = "non-fips")]`
- Keep functions **≤ 50 lines** — extract helpers rather than growing functions
- Use `?` for error propagation — never `.unwrap()` in production code
- Log with correct levels: `trace!` per-request, `debug!` internal state, `info!` lifecycle, `warn!`/`error!` operator-actionable only
