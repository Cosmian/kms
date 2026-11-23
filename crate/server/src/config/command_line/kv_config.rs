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
#[derive(Args, ConfigArgs, Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct KvConfig {
    /// Enable the Vault KV v2-compatible `/<kv_mount>/` scope.
    ///
    /// Defaults to `false`.
    #[clap(
        long = "kv-enabled",
        id = "kv_enabled",
        value_name = "KV_ENABLED",
        env = "KMS_KV_ENABLED",
        default_value = "false"
    )]
    #[serde(rename = "kv_enabled")]
    pub enabled: bool,

    /// KV mount name used by the `/<kv_mount>/data/*` and `/<kv_mount>/metadata/*` routes.
    ///
    /// Mirrors `vault_transit_mount`/`vault_pki_mount`. Defaults to `"kv"`.
    #[clap(
        long = "kv-mount",
        id = "kv_mount",
        value_name = "KV_MOUNT",
        env = "KMS_KV_MOUNT",
        default_value = "kv",
        verbatim_doc_comment
    )]
    #[serde(rename = "kv_mount")]
    pub mount: String,

    /// Interval, in seconds, between KV TTL-expiry sweeps (destroys secret
    /// versions whose `options.ttl` has elapsed). `0` disables the sweep.
    /// Defaults to `30`.
    #[clap(
        long = "kv-ttl-check-interval-secs",
        id = "kv_ttl_check_interval_secs",
        value_name = "KV_TTL_CHECK_INTERVAL_SECS",
        env = "KMS_KV_TTL_CHECK_INTERVAL_SECS",
        default_value = "30"
    )]
    #[serde(rename = "kv_ttl_check_interval_secs")]
    pub ttl_check_interval_secs: u64,
}

/// Hand-written so that a TOML `[kv]` section (parsed with `#[serde(default)]`)
/// and `--print-default-config` agree with the clap default of `30` for
/// `kv_ttl_check_interval_secs`; a derived `Default` would yield `0` and
/// silently disable the TTL sweep. `kv_mount` stays empty (resolved to `"kv"`
/// by `resolve_kv_mount`), like the other `vault_*` mounts.
impl Default for KvConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount: String::new(),
            ttl_check_interval_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::KvConfig;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        kv: KvConfig,
    }

    /// The internal field names are not part of the contract: flags and TOML keys keep their
    /// `kv_` prefix.
    #[test]
    fn kv_config_keeps_flag_and_toml_names() {
        let cli = Cli::try_parse_from([
            "kms",
            "--kv-enabled",
            "--kv-mount",
            "secrets",
            "--kv-ttl-check-interval-secs",
            "7",
        ])
        .expect("the unchanged flags must parse");
        assert!(cli.kv.enabled);
        assert_eq!(cli.kv.mount, "secrets");
        assert_eq!(cli.kv.ttl_check_interval_secs, 7);

        let toml_config: KvConfig = toml::from_str(
            "kv_enabled = true\nkv_mount = \"vault\"\nkv_ttl_check_interval_secs = 0\n",
        )
        .expect("legacy `[kv]` keys must parse");
        assert!(toml_config.enabled);
        assert_eq!(toml_config.mount, "vault");
        assert_eq!(toml_config.ttl_check_interval_secs, 0);

        let serialized = toml::to_string(&KvConfig::default()).expect("serialize");
        assert!(
            serialized.contains("kv_enabled = false")
                && serialized.contains("kv_mount = \"\"")
                && serialized.contains("kv_ttl_check_interval_secs = 30"),
            "{serialized}"
        );
    }
}
