use std::path::PathBuf;

/// Resolved RBAC parameters used at runtime.
///
/// Built from `RbacConfig` during `ServerParams::try_from` with cross-validation
/// against `IdP` config, database state, and policy bundle availability.
#[derive(Debug, Clone)]
pub struct RbacParams {
    /// Whether full RBAC mode is active.
    pub enabled: bool,

    /// Resolved local bundle path (either from direct config or from unpacked remote cache).
    pub bundle_path: Option<PathBuf>,

    /// Remote bundle URL for polling (if configured).
    pub bundle_url: Option<String>,

    /// Polling interval for remote bundle updates.
    pub bundle_poll_interval_secs: u64,

    /// JWT claim path for role extraction (dot-notation for nested claims).
    pub role_claim: String,

    /// JWT claim path for tenant ID extraction.
    pub tenant_claim: String,

    /// Users with super-admin (cross-tenant) privileges.
    pub super_admins: Vec<String>,
}

impl Default for RbacParams {
    fn default() -> Self {
        Self {
            enabled: false,
            bundle_path: None,
            bundle_url: None,
            bundle_poll_interval_secs: 300,
            role_claim: "roles".to_owned(),
            tenant_claim: "tenant_id".to_owned(),
            super_admins: Vec::new(),
        }
    }
}
