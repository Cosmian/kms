// Field names intentionally share a `kv_` prefix for disambiguation in
// flat CLI / env-var namespaces.
#![allow(clippy::struct_field_names)]

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

/// Configuration for the Vault KV v2-compatible secret store (`/kv/` scope).
///
/// When `kv_enabled = true`, the KMS exposes `/<kv_mount>/data/*` and
/// `/<kv_mount>/metadata/*` routes backed by the KMIP `SecretData` object type,
/// following the Vault KV v2 wire format. This lets Vault/`bao`-compatible
/// clients (e.g. the `vault kv` / `bao kv` CLI, `OpenBao`) use the KMS as a
/// generic secrets backend.
#[derive(Args, ConfigArgs, Clone, Debug, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct KvConfig {
    /// Enable the Vault KV v2-compatible `/<kv_mount>/` scope.
    ///
    /// Defaults to `false`.
    #[clap(long, env = "KMS_KV_ENABLED", default_value = "false")]
    pub kv_enabled: bool,

    /// KV mount name used by the `/<kv_mount>/data/*` and `/<kv_mount>/metadata/*` routes.
    ///
    /// Mirrors `vault_transit_mount`/`vault_pki_mount`. Defaults to `"kv"`.
    #[clap(long, env = "KMS_KV_MOUNT", default_value = "kv", verbatim_doc_comment)]
    pub kv_mount: String,

    /// Interval, in seconds, between KV TTL-expiry sweeps (destroys secret
    /// versions whose `options.ttl` has elapsed). `0` disables the sweep.
    /// Defaults to `30`.
    #[clap(long, env = "KMS_KV_TTL_CHECK_INTERVAL_SECS", default_value = "30")]
    pub kv_ttl_check_interval_secs: u64,
}
