pub mod config;
pub mod controller;
pub mod crd;
pub mod error;
pub mod kms;
pub mod webhook;

use std::{sync::Arc, time::Duration};

use cosmian_kms_client::{KmsClientConfig, http_client::HttpClientConfig};
use kube::Client;
use tracing::info;

use crate::{
    config::{InjectArgs, ServeArgs},
    controller::Context,
    error::OperatorError,
};

// ── Serve mode: controller + webhook ─────────────────────────────────────────

pub async fn serve(args: ServeArgs) -> Result<(), OperatorError> {
    let cfg = config::OperatorConfig::from_file(&args.config)?;

    let kms_config = cfg.kms_client_config()?;
    let kms = Arc::new(kms::KmsClientWrapper::new(kms_config)?);

    let k8s = Client::try_default().await.map_err(OperatorError::Kube)?;

    let default_refresh = cfg
        .default_refresh_interval
        .parse::<humantime::Duration>()
        .map_or(Duration::from_secs(3600), Into::into);

    let ctx = Arc::new(Context {
        k8s,
        kms,
        default_refresh,
    });

    info!("starting Cosmian KMS operator");

    // Run controller and webhook concurrently.
    let kms_url = cfg.kms.server_url.clone();
    let api_token_secret_ref = cfg
        .kms
        .api_token_secret_ref
        .as_ref()
        .map(|r| (r.name.clone(), r.key.clone()));
    let webhook_cfg = cfg.webhook.clone();

    tokio::select! {
        () = controller::run(ctx) => {}
        r = webhook::run(
            &webhook_cfg,
            &kms_url,
            api_token_secret_ref.as_ref().map(|(n, k)| (n.as_str(), k.as_str())),
        ) => {
            r?;
        }
    }

    Ok(())
}

// ── Inject mode: init-container, fetches secrets and writes them to disk ──────

pub async fn inject(args: InjectArgs) -> Result<(), OperatorError> {
    let client = kms::KmsClientWrapper::new(KmsClientConfig {
        http_config: HttpClientConfig {
            server_url: args.server_url,
            access_token: args.api_token,
            ..HttpClientConfig::default()
        },
        ..KmsClientConfig::default()
    })?;

    std::fs::create_dir_all(&args.output_dir).map_err(|e| {
        OperatorError::Config(format!("cannot create output dir {}: {e}", args.output_dir))
    })?;

    // Format: "uid1:filename1,uid2:filename2"
    for entry in args
        .secret_uids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (uid, filename) = parse_uid_entry(entry)?;
        info!(uid, filename, "fetching secret");

        let bytes = client.get_secret_bytes(uid).await?;

        let path = std::path::Path::new(&args.output_dir).join(filename);
        std::fs::write(&path, &bytes).map_err(|e| {
            OperatorError::Config(format!("cannot write secret to {}: {e}", path.display()))
        })?;
        // Restrict to owner-read-only (0o400) so secret material is not
        // accessible to other containers sharing the tmpfs volume.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).map_err(
                |e| {
                    OperatorError::Config(format!(
                        "cannot set permissions on {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        info!(path = %path.display(), "secret written");
    }

    Ok(())
}

/// Parse `"<uid>:<filename>"` — both parts are required.
pub fn parse_uid_entry(entry: &str) -> Result<(&str, &str), OperatorError> {
    let mut parts = entry.splitn(2, ':');
    let uid = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        OperatorError::Config(format!("invalid secret-uid entry (missing uid): '{entry}'"))
    })?;
    let filename = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        OperatorError::Config(format!(
            "invalid secret-uid entry (missing filename after ':'): '{entry}'"
        ))
    })?;

    // Prevent path traversal: filename must be a single relative path component.
    let mut comps = std::path::Path::new(filename).components();
    let is_single_normal =
        matches!(comps.next(), Some(std::path::Component::Normal(_))) && comps.next().is_none();
    if !is_single_normal {
        return Err(OperatorError::Config(format!(
            "invalid secret-uid entry (filename must be a single path component): '{entry}'"
        )));
    }

    Ok((uid, filename))
}

// ── CRD mode: dump YAML to stdout ────────────────────────────────────────────

pub fn print_crd() -> Result<(), OperatorError> {
    use std::io::Write as _;

    use kube::CustomResourceExt;

    let crd = crd::KMSSecret::crd();
    let yaml = serde_yaml::to_string(&crd)
        .map_err(|e| OperatorError::Config(format!("CRD serialization error: {e}")))?;
    std::io::stdout()
        .write_all(yaml.as_bytes())
        .map_err(|e| OperatorError::Config(format!("stdout write error: {e}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::parse_uid_entry;

    #[test]
    fn parse_uid_entry_accepts_simple_filename() {
        let (uid, filename) =
            parse_uid_entry("abc-uid:secret.yaml").expect("valid entry should parse");
        assert_eq!(uid, "abc-uid");
        assert_eq!(filename, "secret.yaml");
    }

    #[test]
    fn parse_uid_entry_rejects_path_traversal() {
        assert!(
            parse_uid_entry("uid:../escape").is_err(),
            "path traversal should be rejected"
        );
    }

    #[test]
    fn parse_uid_entry_rejects_absolute_path() {
        assert!(
            parse_uid_entry("uid:/abs/path").is_err(),
            "absolute path should be rejected"
        );
    }

    #[test]
    fn parse_uid_entry_rejects_subdirectory() {
        assert!(
            parse_uid_entry("uid:a/b").is_err(),
            "subdirectory path should be rejected"
        );
    }

    #[test]
    fn parse_uid_entry_rejects_empty_uid() {
        assert!(
            parse_uid_entry(":secret.yaml").is_err(),
            "empty uid should be rejected"
        );
    }

    #[test]
    fn parse_uid_entry_rejects_missing_filename() {
        assert!(
            parse_uid_entry("uid:").is_err(),
            "missing filename should be rejected"
        );
    }

    #[test]
    fn parse_uid_entry_rejects_missing_colon() {
        assert!(
            parse_uid_entry("uid-without-colon").is_err(),
            "entry without colon should be rejected"
        );
    }
}
