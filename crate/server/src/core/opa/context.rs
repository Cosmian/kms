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
