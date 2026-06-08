use std::path::PathBuf;

use clap::Args;
use serde::{Deserialize, Serialize};

/// RBAC / OPA policy authorization configuration.
///
/// When enabled, all KMIP operations and access-management endpoints are authorized
/// via a Rego policy evaluated by the in-process Regorus engine.
///
/// Algorithm enforcement is always delegated to Rego (even without full RBAC).
/// Full RBAC (roles, tenants, ACL bypass) is opt-in via `--rbac-enabled`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Args)]
#[serde(default, deny_unknown_fields)]
pub struct RbacConfig {
    /// Enable full RBAC authorization mode.
    ///
    /// When enabled, the Regorus/OPA policy engine becomes the single authorization
    /// gatekeeper for KMIP operations and access-management endpoints. Legacy DB-level
    /// ACL enforcement is bypassed; ACL state is passed as input to the policy.
    ///
    /// Requires: `IdP` authentication configured, a valid policy bundle path or URL,
    /// and all objects in the database to have a non-NULL `tenant_id`.
    #[clap(long, env = "KMS_RBAC_ENABLED")]
    pub rbac_enabled: bool,

    /// Path to the local policy bundle directory containing `.rego` files.
    ///
    /// The directory must contain an `authz.rego` entry point defining
    /// `data.kms.authz.allow`. All `.rego` files in the directory are loaded
    /// and validated at startup.
    ///
    /// Mutually exclusive with `--rbac-bundle-url` (one must be set when RBAC is enabled).
    #[clap(long, env = "KMS_RBAC_BUNDLE_PATH")]
    pub rbac_bundle_path: Option<PathBuf>,

    /// URL for remote policy bundle retrieval.
    ///
    /// The server downloads an archive from this URL, unpacks it, validates the
    /// `.rego` files, and caches the bundle locally. On sustained unavailability
    /// after startup, the cached bundle is used with a warning.
    ///
    /// Mutually exclusive with `--rbac-bundle-path` (one must be set when RBAC is enabled).
    #[clap(long, env = "KMS_RBAC_BUNDLE_URL")]
    pub rbac_bundle_url: Option<String>,

    /// Polling interval (in seconds) for remote bundle updates.
    ///
    /// Only relevant when `--rbac-bundle-url` is configured.
    /// Default: 300 seconds (5 minutes).
    #[clap(long, env = "KMS_RBAC_BUNDLE_POLL_INTERVAL", default_value = "300")]
    pub rbac_bundle_poll_interval_secs: u64,

    /// JWT claim path for extracting user roles.
    ///
    /// Supports dot-notation for nested claims (e.g., `realm_access.roles`).
    /// The claim value must be a JSON array of strings.
    /// Default: `roles`.
    #[clap(long, env = "KMS_RBAC_ROLE_CLAIM", default_value = "roles")]
    pub rbac_role_claim: String,

    /// JWT claim path for extracting the tenant identifier.
    ///
    /// The claim value must be a string.
    /// Default: `tenant_id`.
    #[clap(long, env = "KMS_RBAC_TENANT_CLAIM", default_value = "tenant_id")]
    pub rbac_tenant_claim: String,

    /// Users with super-admin privileges (cross-tenant access).
    ///
    /// These users are assigned the `super-admin` role via server config,
    /// bypassing tenant isolation. Intended as a break-glass mechanism for
    /// platform operators.
    ///
    /// Can be repeated: `--rbac-super-admin alice@corp.com --rbac-super-admin bob@corp.com`
    #[clap(long = "rbac-super-admin", env = "KMS_RBAC_SUPER_ADMINS")]
    pub rbac_super_admins: Option<Vec<String>>,
}
