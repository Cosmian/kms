use std::{env, path::Path, sync::Mutex};

use cosmian_config_utils::ConfigUtils;
use test_kms_server::TestsContext;

use crate::config::ClientConfig;

/// Protects the check-then-write sequence from TOCTOU races when multiple test
/// threads call this function concurrently for the same server port.
static CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Workspace root path resolved from `CARGO_MANIFEST_DIR`.
fn workspace_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<&'static Path> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        // crate/clients/ckms → 3 levels up to workspace root
        let root = Path::new(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .expect("Failed to find workspace root from CARGO_MANIFEST_DIR");
        // Leak to get 'static lifetime (test-only, acceptable)
        Box::leak(root.to_path_buf().into_boxed_path())
    })
}

/// Load a client config template from `test_data/configs/client/test/{template}`,
/// patch the `server_url` port to match the running test server, resolve relative
/// TLS cert/key paths to absolute paths, write the result to a temp file, and
/// return the path.
///
/// The temp file is cached: subsequent calls with the same template + port + pid
/// return the existing file without rewriting.
pub(crate) fn load_client_config(template: &str, ctx: &TestsContext) -> String {
    let _guard = CONFIG_WRITE_LOCK
        .lock()
        .expect("CONFIG_WRITE_LOCK poisoned");
    let pid = std::process::id();

    // Build a stable temp path keyed by template name, port, and pid
    let stem = template.trim_end_matches(".toml");
    let tmp_path = env::temp_dir()
        .join(format!("{stem}_{}_{pid}.toml", ctx.server_port))
        .to_string_lossy()
        .into_owned();

    if Path::new(&tmp_path).exists() {
        return tmp_path;
    }

    let root = workspace_root();
    let template_path = root.join("test_data/configs/client/test").join(template);

    let mut conf: ClientConfig = ClientConfig::from_toml(
        template_path
            .to_str()
            .expect("template path is valid UTF-8"),
    )
    .unwrap_or_else(|e| panic!("Failed to load client config template {template}: {e}"));

    // Patch server_url with the actual test server port
    let original_url = &conf.kms_config.http_config.server_url;
    let patched_url = patch_port(original_url, ctx.server_port);
    conf.kms_config.http_config.server_url = patched_url;

    // Resolve relative TLS cert/key paths to absolute
    resolve_path(
        &mut conf.kms_config.http_config.tls_client_pem_cert_path,
        root,
    );
    resolve_path(
        &mut conf.kms_config.http_config.tls_client_pem_key_path,
        root,
    );
    resolve_path(
        &mut conf.kms_config.http_config.tls_client_pkcs12_path,
        root,
    );

    conf.to_toml(&tmp_path)
        .unwrap_or_else(|e| panic!("Failed to write patched config to {tmp_path}: {e}"));

    tmp_path
}

/// Convenience: load `auth_plain_owner.toml` patched with ctx port.
pub(crate) fn owner_config(ctx: &TestsContext) -> String {
    load_client_config("auth_plain_owner.toml", ctx)
}

/// Convenience: load `auth_plain_user.toml` patched with ctx port.
pub(crate) fn user_config(ctx: &TestsContext) -> String {
    load_client_config("auth_plain_user.toml", ctx)
}

/// Replace the port in a URL string, preserving scheme/host/path.
fn patch_port(url: &str, port: u16) -> String {
    // Simple approach: find `:PORT` after host and replace it
    // URLs are always `http(s)://host:port` in our templates
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(colon_pos) = after_scheme.find(':') {
            let host = &after_scheme[..colon_pos];
            let scheme = &url[..scheme_end];
            // Check for path after port
            let after_port = &after_scheme[colon_pos + 1..];
            let path = after_port
                .find('/')
                .map_or("", |slash| &after_port[slash..]);
            return format!("{scheme}://{host}:{port}{path}");
        }
    }
    // Fallback: just append port (shouldn't happen with our templates)
    format!("{url}:{port}")
}

/// If the option contains a relative path, make it absolute relative to `root`.
fn resolve_path(opt: &mut Option<String>, root: &Path) {
    if let Some(path_str) = opt.as_ref() {
        let p = Path::new(path_str);
        if p.is_relative() {
            *opt = Some(root.join(p).to_string_lossy().into_owned());
        }
    }
}

/// Dynamically save the server's owner and user client configs to temp files.
/// Unlike `load_client_config` which loads a static template, this serializes
/// the actual `TestsContext` configs — essential for auth tests where each
/// server has unique auth settings (JWT, certs, API tokens, etc.).
pub(crate) fn force_save_kms_cli_config(ctx: &TestsContext) -> (String, String) {
    let pid = std::process::id();

    let owner_file_path = env::temp_dir()
        .join(format!("owner_{}_{}.toml", ctx.server_port, pid))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: ctx.owner_client_config.clone(),
    };
    conf.to_toml(&owner_file_path)
        .expect("Failed to save owner test config");

    let user_file_path = env::temp_dir()
        .join(format!("user_{}_{}.toml", ctx.server_port, pid))
        .to_string_lossy()
        .into_owned();
    let conf = ClientConfig {
        kms_config: ctx.user_client_config.clone(),
    };
    conf.to_toml(&user_file_path)
        .expect("Failed to save user test config");

    (owner_file_path, user_file_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_port() {
        assert_eq!(
            patch_port("http://localhost:12001", 9999),
            "http://localhost:9999"
        );
        assert_eq!(
            patch_port("https://localhost:10003", 8888),
            "https://localhost:8888"
        );
        assert_eq!(
            patch_port("http://127.0.0.1:9998/api", 5555),
            "http://127.0.0.1:5555/api"
        );
    }
}
