//! Advanced / miscellaneous configuration step of the KMS configuration wizard.
//!
//! Covers: workspace paths, key management, vendor identification, Microsoft
//! DKE, KMS public URL, KMIP policy, Google CSE, Azure EKM, AWS XKS, and UI
//! settings.

#![allow(unreachable_pub)]

use std::{collections::HashMap, path::PathBuf};

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN, kmip_objects::ObjectType,
};
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use strum::IntoEnumIterator;

use super::PromptResultExt;
use crate::{
    config::{
        AzureEkmConfig, EstConfig, GoogleCseConfig, KmipPolicyConfig, KmipPolicyId, ScepConfig,
        TlsConfig, UiConfig, WorkspaceConfig,
    },
    core::operations::certify::template::CertTemplate,
    error::KmsError,
    result::KResult,
    routes::aws_xks::AwsXksConfig,
};

/// Name of the certificate template the wizard generates for EST / SCEP.
const ENROLLMENT_TEMPLATE: &str = "enrollment";

pub struct AdvancedConfig {
    pub workspace: WorkspaceConfig,
    pub vendor_identification: String,
    pub key_encryption_key: Option<String>,
    pub key_encryption_key_wrapping_algorithm: Option<String>,
    pub default_unwrap_type: Option<Vec<String>>,
    pub crypto_officer_users: Option<Vec<String>>,
    pub crypto_officer_require_ceremony: bool,
    pub ms_dke_service_url: Option<String>,
    pub kms_public_url: Option<String>,
    pub kmip_policy: KmipPolicyConfig,
    pub google_cse_config: GoogleCseConfig,
    pub azure_ekm_config: AzureEkmConfig,
    pub aws_xks_config: AwsXksConfig,
    pub est: EstConfig,
    pub scep: ScepConfig,
    pub templates: HashMap<String, CertTemplate>,
    pub ui_config: UiConfig,
}

pub fn configure_advanced(mut ui: UiConfig, tls: &TlsConfig) -> KResult<AdvancedConfig> {
    let theme = ColorfulTheme::default();

    // ── Workspace ─────────────────────────────────────────────────────────────
    let root_data_path: String = Input::with_theme(&theme)
        .with_prompt("KMS data root directory")
        .default("./cosmian-kms".to_owned())
        .interact_text()
        .prompt_err()?;

    // Create the root data directory immediately for early validation.
    let root_data_pb = PathBuf::from(&root_data_path);
    std::fs::create_dir_all(&root_data_pb).map_err(|e| {
        KmsError::ServerError(format!(
            "Cannot create root data directory '{}': {e}",
            root_data_pb.display()
        ))
    })?;

    #[cfg(not(target_os = "windows"))]
    let default_tmp = "/tmp".to_owned();
    #[cfg(target_os = "windows")]
    let default_tmp = std::env::temp_dir()
        .to_str()
        .unwrap_or("C:\\Temp")
        .to_owned();

    let tmp_path: String = Input::with_theme(&theme)
        .with_prompt("Temporary data directory")
        .default(default_tmp)
        .interact_text()
        .prompt_err()?;

    // Create the temporary directory immediately for early validation.
    let tmp_pb = PathBuf::from(&tmp_path);
    std::fs::create_dir_all(&tmp_pb).map_err(|e| {
        KmsError::ServerError(format!(
            "Cannot create temporary directory '{}': {e}",
            tmp_pb.display()
        ))
    })?;

    let workspace = WorkspaceConfig {
        root_data_path: PathBuf::from(root_data_path),
        tmp_path: PathBuf::from(tmp_path),
    };

    // ── Vendor Identification ─────────────────────────────────────────────────
    let vendor_identification: String = Input::with_theme(&theme)
        .with_prompt(
            "Vendor identification string (reported in KMIP QueryServerInformation; \
             leave blank to use the default 'cosmian')",
        )
        .default(VENDOR_ID_COSMIAN.to_owned())
        .interact_text()
        .prompt_err()?;

    // ── Key Management ────────────────────────────────────────────────────────
    let kek: String = Input::with_theme(&theme)
        .with_prompt(
            "Key Encryption Key (KEK) ID to wrap all keys at rest \
             (leave blank to disable)",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    let key_encryption_key = if kek.trim().is_empty() {
        None
    } else {
        Some(kek)
    };
    let key_encryption_key_wrapping_algorithm = if key_encryption_key.is_some() {
        let items = [
            "default (HSM: AES-GCM or RSA-OAEP; software: AES-KWP)",
            "aes-gcm",
            "aes-key-wrap",
            "aes-key-wrap-padding",
            "rsa-oaep",
        ];
        let idx = Select::with_theme(&theme)
            .with_prompt("Algorithm used to wrap keys at rest with the KEK")
            .items(&items)
            .default(0)
            .interact()
            .prompt_err()?;
        (idx > 0)
            .then(|| items.get(idx).map(|s| (*s).to_owned()))
            .flatten()
    } else {
        None
    };

    let mut unwrap_type_labels: Vec<&str> = vec!["All"];
    unwrap_type_labels.extend(ObjectType::iter().map(|t| -> &'static str { t.into() }));
    let selected_unwrap = MultiSelect::with_theme(&theme)
        .with_prompt(
            "Object types to auto-unwrap when retrieved \
             (space to toggle, enter to confirm; select none to disable)",
        )
        .items(&unwrap_type_labels)
        .interact()
        .prompt_err()?;
    let default_unwrap_type = if selected_unwrap.is_empty() {
        None
    } else {
        Some(
            selected_unwrap
                .iter()
                .filter_map(|&i| unwrap_type_labels.get(i).copied())
                .map(ToOwned::to_owned)
                .collect(),
        )
    };

    let crypto_officer_str: String = Input::with_theme(&theme)
        .with_prompt(
            "Crypto Officer users who can create/import/certify objects \
             (comma-separated, leave blank to skip — formerly 'privileged_users')",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    let crypto_officer_users = if crypto_officer_str.trim().is_empty() {
        None
    } else {
        Some(
            crypto_officer_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    // ── Ceremony mode ─────────────────────────────────────────────────────────
    // Prompt only when CO users were actually configured. Without ceremony mode
    // every CO candidate is permanently active (security warning logged at startup).
    let crypto_officer_require_ceremony = if crypto_officer_users.is_some() {
        Confirm::with_theme(&theme)
            .with_prompt(
                "Require a split-key ceremony to activate the Crypto Officer role?\n  \
                 (Recommended: yes — prevents permanent super-admin without runtime activation)\n  \
                 Ceremony requires `ceremony_secret` or `ceremony_key_id` in kms.toml.",
            )
            .default(true)
            .interact()
            .prompt_err()?
    } else {
        false
    };

    // ── Microsoft DKE & Public URL ────────────────────────────────────────────
    let ms_dke: String = Input::with_theme(&theme)
        .with_prompt(
            "Microsoft DKE service URL (leave blank to disable, \
             e.g. https://cse.my_domain.com/ms_dke)",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    let ms_dke_service_url = if ms_dke.trim().is_empty() {
        None
    } else {
        Some(ms_dke)
    };

    let public_url: String = Input::with_theme(&theme)
        .with_prompt(
            "KMS public URL (required for Google CSE / UI auth flows; leave blank to skip)",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    let kms_public_url = if public_url.trim().is_empty() {
        None
    } else {
        Some(public_url)
    };

    // ── KMIP Policy ───────────────────────────────────────────────────────────
    let mut policy_items: Vec<&str> = vec!["(disabled)"];
    policy_items.extend(KmipPolicyId::VARIANTS.iter().map(|v| v.as_str()));
    let policy_idx = Select::with_theme(&theme)
        .with_prompt("KMIP algorithm policy")
        .items(&policy_items)
        .default(0)
        .interact()
        .prompt_err()?;
    let kmip_policy = KmipPolicyConfig {
        policy_id: if policy_idx == 0 {
            None
        } else {
            KmipPolicyId::VARIANTS
                .get(policy_idx - 1)
                .map(|v| v.as_str().to_owned())
        },
        allowlists: KmipPolicyConfig::unrestricted_allowlists(),
    };

    // ── Google CSE ────────────────────────────────────────────────────────────
    let google_cse_config = configure_google_cse(&theme)?;

    // ── Azure EKM ─────────────────────────────────────────────────────────────
    let azure_ekm_config = configure_azure_ekm(&theme)?;

    // ── AWS XKS ───────────────────────────────────────────────────────────────
    let aws_xks_config = configure_aws_xks(&theme)?;

    // ── UI dist path ──────────────────────────────────────────────────────────
    let ui_dist: String = Input::with_theme(&theme)
        .with_prompt("UI distribution folder path")
        .default(crate::config::get_default_ui_dist_path())
        .interact_text()
        .prompt_err()?;
    ui.ui_index_html_folder = Some(ui_dist);

    let session_salt: String = Input::with_theme(&theme)
        .with_prompt(
            "Session cookie salt (leave blank to auto-generate; \
             must match across load-balanced instances)",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    ui.ui_session_salt = if session_salt.trim().is_empty() {
        None
    } else {
        Some(session_salt)
    };
    ui.enable = true;

    // ── EST / SCEP enrollment ─────────────────────────────────────────────────
    let (est, scep, templates) = configure_enrollment(&theme, tls)?;

    Ok(AdvancedConfig {
        workspace,
        vendor_identification,
        key_encryption_key,
        key_encryption_key_wrapping_algorithm,
        default_unwrap_type,
        crypto_officer_users,
        crypto_officer_require_ceremony,
        ms_dke_service_url,
        kms_public_url,
        kmip_policy,
        google_cse_config,
        azure_ekm_config,
        aws_xks_config,
        est,
        scep,
        templates,
        ui_config: ui,
    })
}

fn configure_google_cse(theme: &ColorfulTheme) -> KResult<GoogleCseConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable Google Client-Side Encryption (CSE) endpoints?")
        .default(false)
        .interact()
        .prompt_err()?;

    if !enable {
        return Ok(GoogleCseConfig::default());
    }

    let disable_validation: bool = Confirm::with_theme(theme)
        .with_prompt("Disable Google CSE token validation? (not recommended for production)")
        .default(false)
        .interact()
        .prompt_err()?;

    let whitelist_str: String = Input::with_theme(theme)
        .with_prompt(
            "CSE incoming URL whitelist for migration (comma-separated; leave blank to skip)",
        )
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;
    let google_cse_incoming_url_whitelist = if whitelist_str.trim().is_empty() {
        None
    } else {
        Some(
            whitelist_str
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };

    let migration_key: String = Input::with_theme(theme)
        .with_prompt("CSE migration key (PEM PKCS#8 RSA key; leave blank to auto-generate)")
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;

    Ok(GoogleCseConfig {
        google_cse_enable: true,
        google_cse_disable_tokens_validation: disable_validation,
        google_cse_incoming_url_whitelist,
        google_cse_migration_key: if migration_key.trim().is_empty() {
            None
        } else {
            Some(migration_key)
        },
    })
}

/// EST / SCEP device enrollment. The CA must already exist in the KMS (create it with
/// `ckms certificates certify`, then delegate it to `[enrollment-service]`, see the PKI
/// enrollment guide); the server re-validates every value at startup.
#[expect(
    clippy::print_stdout,
    reason = "the configuration wizard prompts the user on stdout"
)]
fn configure_enrollment(
    theme: &ColorfulTheme,
    tls: &TlsConfig,
) -> KResult<(EstConfig, ScepConfig, HashMap<String, CertTemplate>)> {
    let mut est = EstConfig::default();
    let mut scep = ScepConfig::default();
    let mut templates = HashMap::new();

    est.est_enabled = Confirm::with_theme(theme)
        .with_prompt("Enable EST (RFC 7030) device enrollment endpoints?")
        .default(false)
        .interact()
        .prompt_err()?;
    scep.scep_enabled = Confirm::with_theme(theme)
        .with_prompt("Enable SCEP (RFC 8894) device enrollment endpoint?")
        .default(false)
        .interact()
        .prompt_err()?;
    if est.est_enabled && !tls.is_tls_enabled() {
        println!(
            "  ⚠  EST requires TLS (RFC 7030 §3.3) but no TLS certificate is configured: \
             EST is left disabled. Configure TLS, then enable it in the config file."
        );
        est.est_enabled = false;
    }
    if !est.est_enabled && !scep.scep_enabled {
        return Ok((est, scep, templates));
    }
    if est.est_enabled {
        let ca: String = Input::with_theme(theme)
            .with_prompt(
                "EST: unique identifier of the CA certificate that signs enrolled certificates",
            )
            .interact_text()
            .prompt_err()?;
        est.est_ca_uid = Some(ca.trim().to_owned());
        // Mutual TLS needs a client CA to validate the presented certificate.
        if tls.clients_ca_cert_file.is_some() {
            est.est_require_client_cert = Confirm::with_theme(theme)
                .with_prompt(
                    "EST: require a TLS client certificate for initial enrollment? \
                     (no = HTTP Basic bootstrap credentials)",
                )
                .default(true)
                .interact()
                .prompt_err()?;
        } else {
            println!(
                "  ℹ  No clients CA certificate is configured: EST uses HTTP Basic bootstrap credentials."
            );
            est.est_require_client_cert = false;
        }
        if !est.est_require_client_cert {
            let user: String = Input::with_theme(theme)
                .with_prompt("EST: bootstrap username (must not contain ':')")
                .validate_with(|u: &String| -> Result<(), &str> {
                    if u.trim().is_empty() || u.contains(':') {
                        Err("must be non-empty and must not contain ':'")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()
                .prompt_err()?;
            let password: String = dialoguer::Password::with_theme(theme)
                .with_prompt("EST: bootstrap password (at least 8 characters)")
                .with_confirmation("Confirm password", "Passwords do not match")
                .validate_with(|p: &String| -> Result<(), &str> {
                    if p.trim().chars().count() < 8 {
                        Err("at least 8 characters are required")
                    } else {
                        Ok(())
                    }
                })
                .interact()
                .prompt_err()?;
            est.est_bootstrap_username = Some(user.trim().to_owned());
            est.est_bootstrap_password = Some(password);
        }
    }
    if scep.scep_enabled {
        let ca: String = Input::with_theme(theme)
            .with_prompt("SCEP: unique identifier of the RSA CA certificate that signs enrolled certificates")
            .interact_text().prompt_err()?;
        scep.scep_ca_uid = Some(ca.trim().to_owned());
        let challenge: String = dialoguer::Password::with_theme(theme)
            .with_prompt("SCEP: challenge password devices must present (at least 8 characters)")
            .with_confirmation("Confirm password", "Passwords do not match")
            .validate_with(|p: &String| -> Result<(), &str> {
                if p.trim().chars().count() < 8 {
                    Err("at least 8 characters are required")
                } else {
                    Ok(())
                }
            })
            .interact()
            .prompt_err()?;
        scep.scep_challenge_password = Some(challenge);
    }

    // The enrollment secret authenticates a class of devices, not the name a device asks for:
    // the template must constrain the subject CN (`.*` explicitly accepts any CN).
    let valid_regex = |r: &String| -> Result<(), String> {
        regex::Regex::new(r.trim())
            .and_then(|_| regex::Regex::new(&format!("^(?:{})$", r.trim())))
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    let cn_regex: String = Input::with_theme(theme)
        .with_prompt(
            "Regular expression every enrolled subject CN must match, anchored \
             (required; `.*` accepts any CN)",
        )
        .validate_with(valid_regex)
        .interact_text()
        .prompt_err()?;
    // SANs are default-deny: without a pattern, CSRs carrying DNS SANs are refused.
    let san_dns_regex: String = Input::with_theme(theme)
        .with_prompt(
            "Regular expression every DNS subject alternative name must match, anchored \
             (leave blank to refuse CSRs with DNS SANs)",
        )
        .allow_empty(true)
        .validate_with(valid_regex)
        .interact_text()
        .prompt_err()?;
    templates.insert(
        ENROLLMENT_TEMPLATE.to_owned(),
        CertTemplate {
            name: ENROLLMENT_TEMPLATE.to_owned(),
            subject_cn_regex: Some(cn_regex.trim().to_owned()),
            san_dns_regex: Some(san_dns_regex.trim().to_owned()).filter(|r| !r.is_empty()),
            ..CertTemplate::default()
        },
    );
    if est.est_enabled {
        est.est_template = Some(ENROLLMENT_TEMPLATE.to_owned());
    }
    if scep.scep_enabled {
        scep.scep_template = Some(ENROLLMENT_TEMPLATE.to_owned());
    }
    println!(
        "  ℹ  The enrollment endpoints are reachable before authentication: set \
         rate_limit_per_second in the configuration file for production. The file is written \
         readable by its owner only because it contains the enrollment secrets."
    );
    println!(
        "  Next: grant the CA to the enrollment service identity:\n    \
         ckms access-rights grant \"[enrollment-service]\" -i <ca uid> certify\n  \
         (and the same for the CA private key; plus `create` when Crypto Officers are \
         configured)."
    );
    Ok((est, scep, templates))
}

fn configure_azure_ekm(theme: &ColorfulTheme) -> KResult<AzureEkmConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable Azure EKM proxy endpoints?")
        .default(false)
        .interact()
        .prompt_err()?;

    if !enable {
        return Ok(AzureEkmConfig::default());
    }

    let path_prefix: String = Input::with_theme(theme)
        .with_prompt("Azure EKM path prefix (leave blank to skip)")
        .allow_empty(true)
        .interact_text()
        .prompt_err()?;

    let disable_client_auth: bool = Confirm::with_theme(theme)
        .with_prompt("⚠  Disable mTLS client auth? (testing only)")
        .default(false)
        .interact()
        .prompt_err()?;

    let proxy_vendor: String = Input::with_theme(theme)
        .with_prompt("EKM proxy vendor name")
        .default("Cosmian".to_owned())
        .interact_text()
        .prompt_err()?;

    let proxy_name: String = Input::with_theme(theme)
        .with_prompt("EKM proxy name")
        .default("EKM Proxy Service".to_owned())
        .interact_text()
        .prompt_err()?;

    let ekm_vendor: String = Input::with_theme(theme)
        .with_prompt("EKMS vendor name")
        .default("Cosmian".to_owned())
        .interact_text()
        .prompt_err()?;

    let ekm_product: String = Input::with_theme(theme)
        .with_prompt("EKMS product name and version")
        .default(format!("Cosmian KMS v{}", env!("CARGO_PKG_VERSION")))
        .interact_text()
        .prompt_err()?;

    Ok(AzureEkmConfig {
        azure_ekm_enable: true,
        azure_ekm_path_prefix: if path_prefix.trim().is_empty() {
            None
        } else {
            Some(path_prefix)
        },
        azure_ekm_disable_client_auth: disable_client_auth,
        azure_ekm_proxy_vendor: proxy_vendor,
        azure_ekm_proxy_name: proxy_name,
        azure_ekm_ekm_vendor: ekm_vendor,
        azure_ekm_ekm_product: ekm_product,
    })
}

fn configure_aws_xks(theme: &ColorfulTheme) -> KResult<AwsXksConfig> {
    let enable: bool = Confirm::with_theme(theme)
        .with_prompt("Enable AWS External Key Store (XKS) endpoints?")
        .default(false)
        .interact()
        .prompt_err()?;

    if !enable {
        return Ok(AwsXksConfig::default());
    }

    let region: String = Input::with_theme(theme)
        .with_prompt("AWS region (for SigV4 signing)")
        .interact_text()
        .prompt_err()?;

    let service: String = Input::with_theme(theme)
        .with_prompt("AWS service name (for SigV4 signing)")
        .default("kms".to_owned())
        .interact_text()
        .prompt_err()?;

    let access_key_id: String = Input::with_theme(theme)
        .with_prompt("AWS XKS SigV4 access key ID")
        .interact_text()
        .prompt_err()?;

    let secret_access_key: String = dialoguer::Password::with_theme(theme)
        .with_prompt("AWS XKS SigV4 secret access key")
        .interact()
        .prompt_err()?;

    Ok(AwsXksConfig {
        aws_xks_enable: true,
        aws_xks_region: Some(region),
        aws_xks_service: Some(service),
        aws_xks_sigv4_access_key_id: Some(access_key_id),
        aws_xks_sigv4_secret_access_key: Some(secret_access_key),
    })
}
