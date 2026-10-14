//! Per-request OPA user context stored in a task-local variable.
//!
//! Using `tokio::task_local!` (rather than `thread_local!`) ensures the context
//! is bound to the logical async *task* (i.e. a single HTTP request) and not to
//! the underlying OS thread.  With a multi-threaded Tokio runtime, tasks can
//! migrate between OS threads on every `.await` point; a `thread_local!` value
//! set before an `.await` may therefore be invisible — or, worse, belong to a
//! *different* request — when the task resumes on another thread.
//!
//! Route handlers that perform OPA-guarded operations must wrap their async work
//! in `OPA_USER_CONTEXT.scope(ctx, fut).await` to set the context for the
//! duration of that future.

use tokio::task_local;

/// Per-request context for OPA policy evaluation.
#[derive(Debug, Clone, Default)]
pub(crate) struct OpaUserContext {
    /// RBAC roles from the JWT (empty if not present or not authenticated via JWT).
    pub roles: Vec<String>,
    /// Domain from the JWT `as_domain` private claim.
    pub domain: Option<String>,
}

task_local! {
    /// Task-local OPA user context.  Valid only within a `scope()` block set by
    /// the route handler.  Defaults to an empty context if accessed outside a scope
    /// (e.g. in tests that do not configure OPA), which results in fail-closed OPA
    /// behavior.
    pub(crate) static OPA_USER_CONTEXT: OpaUserContext;
}

/// Read the OPA user context for the current task.
/// Returns an empty (zero-privilege) context when called outside a scope.
pub(crate) fn get_opa_user_context() -> OpaUserContext {
    OPA_USER_CONTEXT.try_with(Clone::clone).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ── OpaUserContext::default ──────────────────────────────────────────────

    /// Default context must be zero-privilege: empty roles and no domain.
    /// This is the fail-closed starting state for any request that did not
    /// set an explicit context.
    #[test]
    fn test_opa_user_context_default_zero_privilege() {
        let ctx = OpaUserContext::default();
        assert!(ctx.roles.is_empty(), "default roles must be empty");
        assert!(ctx.domain.is_none(), "default domain must be None");
    }

    // ── get_opa_user_context outside scope ───────────────────────────────────

    /// Calling `get_opa_user_context()` outside of an `OPA_USER_CONTEXT.scope()`
    /// must return the default zero-privilege context instead of panicking.
    /// This is critical for correctness: operations that don't set a context
    /// must fail-closed (no roles → OPA denies).
    #[tokio::test]
    async fn test_get_opa_user_context_outside_scope_returns_default() {
        let ctx = get_opa_user_context();
        assert!(ctx.roles.is_empty());
        assert!(ctx.domain.is_none());
    }

    // ── get_opa_user_context within scope ────────────────────────────────────

    /// Inside `OPA_USER_CONTEXT.scope(ctx, fut)`, `get_opa_user_context()`
    /// must return exactly the value that was placed in scope.
    #[tokio::test]
    async fn test_get_opa_user_context_within_scope_returns_value() {
        let expected = OpaUserContext {
            roles: vec!["CryptoOfficer".to_owned()],
            domain: Some("acme.com".to_owned()),
        };
        let result = OPA_USER_CONTEXT
            .scope(expected.clone(), async { get_opa_user_context() })
            .await;
        assert_eq!(result.roles, expected.roles);
        assert_eq!(result.domain, expected.domain);
    }

    /// After the scope future completes, `get_opa_user_context()` reverts to
    /// the default — the task-local is not leaked across scope boundaries.
    #[tokio::test]
    async fn test_get_opa_user_context_scope_does_not_leak() {
        let ctx = OpaUserContext {
            roles: vec!["SuperAdmin".to_owned()],
            domain: Some("leak-test".to_owned()),
        };
        OPA_USER_CONTEXT.scope(ctx, async { /* nothing */ }).await;
        // After the scope, the task-local is no longer set.
        let after = get_opa_user_context();
        assert!(
            after.roles.is_empty(),
            "roles must be empty after scope exits, got {:?}",
            after.roles
        );
        assert!(after.domain.is_none());
    }

    /// Scopes with different contexts can be nested: the inner scope's value
    /// is visible inside, and the outer scope's value is visible outside.
    #[tokio::test]
    async fn test_get_opa_user_context_nested_scopes() {
        let outer = OpaUserContext {
            roles: vec!["DomainAdmin".to_owned()],
            domain: Some("outer.com".to_owned()),
        };
        let inner = OpaUserContext {
            roles: vec!["Auditor".to_owned()],
            domain: Some("inner.com".to_owned()),
        };
        let (outer_seen, inner_seen) = OPA_USER_CONTEXT
            .scope(outer.clone(), async {
                let outer_ctx = get_opa_user_context();
                let inner_ctx = OPA_USER_CONTEXT
                    .scope(inner.clone(), async { get_opa_user_context() })
                    .await;
                (outer_ctx, inner_ctx)
            })
            .await;
        assert_eq!(outer_seen.roles, outer.roles);
        assert_eq!(inner_seen.roles, inner.roles);
    }
}
