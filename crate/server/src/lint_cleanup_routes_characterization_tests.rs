//! Characterization tests pinning BASE behavior of `routes/**`, `middlewares/**`, `config/**`.
//!
//! Private items of those modules are pinned by per-file `*_characterization_tests.rs` modules
//! (`routes/google_cse/operations.rs`, `routes/spire/pki.rs`, `routes/ms_dke/mod.rs`,
//! `routes/aws_xks/mod.rs`, `routes/jose/error.rs`); this file pins what is reachable from the
//! crate root: the configuration, its redaction, and REST response shapes.

use std::sync::Arc;

use actix_web::{App, test as actix_test, web::Data};

use crate::{
    config::{ClapConfig, ServerParams},
    core::KMS,
    openssl_providers::init_openssl_providers_for_tests,
    routes::access::get_crypto_officer_status,
    tests::test_utils::https_clap_config,
};

#[cfg(not(windows))]
const PRINT_DEFAULT: &str = "--print-default-config";

#[cfg(not(windows))]
fn parse(flags: &[&str]) -> ClapConfig {
    let mut args = vec!["cosmian_kms", PRINT_DEFAULT];
    args.extend_from_slice(flags);
    ClapConfig::load_from_args(args).unwrap()
}

// The default configuration is platform specific (Windows binds 127.0.0.1, has no syslog option
// and different default paths): the next items pin the Unix defaults only.
#[cfg(not(windows))]
const DEFAULT_TOML: &str = r#"vendor_identification = "cosmian"
default_username = "admin"
force_default_username = false
info = false
hsm_model = ""
hsm_admin = []
hsm_slot = []
hsm_password = []
hsm_instances = []
auto_rotation_check_interval_secs = 0
metrics_count_interval_secs = 30
keyset_warn_depth = 5

[db]
sqlite_path = "./sqlite-data"
clear_database = false
unwrapped_cache_max_age = 15
unwrapped_cache_max_size = 1000
disable_unwrapped_cache = false

[socket_server]
socket_server_start = false
socket_server_port = 5696
socket_server_hostname = "0.0.0.0"

[tls]

[http]
port = 9998
hostname = "0.0.0.0"

[proxy]

[idp_auth]
jwt_svid_auth = false

[auth_verifier]
auth_verifier_accept_invalid_certs = false

[ui_config]
enable = false

[ui_config.ui_oidc_auth]

[google_cse_config]
google_cse_enable = false
google_cse_disable_tokens_validation = false

[azure_ekm_config]
azure_ekm_enable = false

[workspace]
root_data_path = "./cosmian-kms"
tmp_path = "/tmp"

[logging]
otlp_allow_insecure = false
quiet = false
log_to_syslog = false
enable_metering = false
ansi_colors = false

[roles]
crypto_officer_require_ceremony = false

[aws_xks_config]
aws_xks_enable = false

[kmip.allowlists]

[jwks_endpoint]
jwks_endpoint_enabled = false
jwks_endpoint_max_keys = 50
jwks_endpoint_auto_tag = true

[vault]
vault_api_enabled = false
vault_auth_verifier_accept_invalid_certs = false
vault_transit_mount = ""
vault_pki_mount = ""
vault_pki_ca_key_label = ""
vault_token_cache_ttl_secs = 0

[audit]
enabled = false
channel_capacity = 0
trusted_proxy_cidrs = []
failure_mode = "continue"

[audit.file]

[audit.postgres]

[crl]
crl_default_validity_days = 7
crl_refresh_check_hours = 1
crl_refresh_overlap_hours = 24

[ocsp]
ocsp_enabled = false
ocsp_cache_ttl_secs = 86400
ocsp_nonce_policy = "optional"
ocsp_include_cert_chain = true
ocsp_archive_cutoff_secs = 0
"#;

#[cfg(not(windows))]
#[test]
fn characterization_clap_config_default_toml() {
    let rendered = toml::to_string(&ClapConfig::default()).unwrap();
    assert_eq!(rendered, DEFAULT_TOML);
    let round_trip: ClapConfig = toml::from_str(&rendered).unwrap();
    assert_eq!(toml::to_string(&round_trip).unwrap(), DEFAULT_TOML);
}

#[cfg(not(windows))]
#[test]
fn characterization_clap_config_flags_and_redaction() {
    let secret = "s3cr3t-pw";
    let c = parse(&[
        "--port",
        "9999",
        "--hostname",
        "example.org",
        "--proxy-url",
        "http://p:3128",
        "--proxy-basic-auth-username",
        "alice",
        "--proxy-basic-auth-password",
        secret,
        "--proxy-exclusion-list",
        "a.com",
        "--socket-server-start",
        "--socket-server-port",
        "6000",
        "--database-type",
        "sqlite",
        "--sqlite-path",
        "/tmp/x.db",
        "--vault-pki-ca-key-label",
        "lbl",
    ]);
    assert!(c.print_default_config);
    assert_eq!(c.http.port, 9999);
    assert_eq!(c.http.hostname, "example.org");
    assert_eq!(c.socket_server.socket_server_port, 6000);
    assert!(c.socket_server.socket_server_start);
    assert_eq!(c.db.database_type.as_deref(), Some("sqlite"));
    assert_eq!(c.vault.vault_pki_ca_key_label, "lbl");
    assert_eq!(
        c.proxy.to_string(),
        r#"Proxy URL: http://p:3128, Basic Auth Username: alice, Basic Auth Password: ***, No Custom Auth Header, No Proxy Exclusion List: ["a.com"]"#
    );
    assert_eq!(c.socket_server.to_string(), "tls socket: 0.0.0.0:6000");
    assert_eq!(
        c.db.to_string(),
        "sqlite: /tmp/x.db, clear_database?: false"
    );
    assert_eq!(c.http.to_string(), "example.org:9999");
    let debug = format!("{c:?}");
    assert!(!debug.contains(secret));
    assert!(debug.starts_with(
        r#" { config_path: None, print_default_config: true, db: sqlite: /tmp/x.db, clear_database?: false, proxy: Proxy URL: http://p:3128, Basic Auth Username: alice, Basic Auth Password: ***, No Custom Auth Header, No Proxy Exclusion List: ["a.com"], socket server: tls socket: 0.0.0.0:6000, TLS: No TLS config, socket server: tls socket: 0.0.0.0:6000, ui_index_html_folder: "#
    ));
    assert!(debug.contains(
        r#", KMS http: "http://example.org:9999", KMS public URL: None, workspace: WorkspaceConfig { root_data_path: "./cosmian-kms", tmp_path: "/tmp" }, vendor identification: "cosmian", default username: "admin", force default username: false, google_cse_enable: false, azure_ekm_enable: false, Microsoft Double Key Encryption URL: None"#
    ));
    let params = ServerParams::try_from(c).unwrap();
    let params_debug = format!("{params:?}");
    // BASE behavior: `ProxyParams`'s Debug prints the proxy password in clear text.
    assert!(params_debug.contains(r#"basic_auth_password: Some("s3cr3t-pw")"#));
    assert!(params_debug.starts_with(
        r#"ServerParams { jwt_svid_auth_enabled: false, default_username: "admin", force_default_username: false, vendor_identification: "cosmian", main_db_params: sqlite: "#
    ));
    assert!(params_debug.contains(
        r#"x.db, clear_db_on_start: false, unwrapped_cache_max_age: 900s, unwrapped_cache_max_size: 1000, unwrapped_cache_max_ttl: None, disable_unwrapped_cache: false, otel_params: OpenTelemetryConfig { otlp_url: None, otlp_allow_insecure: false, enable_metering: false, environment: Some("development") }, kmip_policy_id: None, kmip_algorithm_policy: "no restrictions — all supported algorithms are allowed", socket_server_hostname: "0.0.0.0", socket_server_port: 6000, google_cse_enable: false, aws_xks_params: "not configured", azure_ekm_enable: false, hsm_instances: "no HSM configure"#
    ));
}

#[tokio::test]
async fn characterization_get_crypto_officer_status_without_role() {
    init_openssl_providers_for_tests();
    let kms = Arc::new(
        KMS::instantiate(Arc::new(
            ServerParams::try_from(https_clap_config()).unwrap(),
        ))
        .await
        .unwrap(),
    );
    let app = actix_test::init_service(
        App::new()
            .app_data(Data::new(kms))
            .service(get_crypto_officer_status),
    )
    .await;
    let req = actix_test::TestRequest::get()
        .uri("/access/crypto_officer/status")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = actix_test::read_body(resp).await;
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        r#"{"enabled":false,"users":[],"active_co_users":[],"custodians_count":0,"require_ceremony":false,"ceremony_activated":false,"is_crypto_officer":false}"#
    );
}
