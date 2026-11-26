//! `ckms ssh`: manage the KMS-hosted OpenSSH certificate authority and request certificates
//! (`/v1/ssh/*`), and `ckms password`.
//!
//! Vocabulary, as used by the server:
//! - the **CA** is a KMS key pair whose private key signs the certificates;
//! - a **role** is a signing policy: which principals it may certify, the default and maximum
//!   certificate lifetime, and which KMS users may request certificates with it;
//! - a **principal** is a name embedded in the certificate (a login name for a user
//!   certificate): `sshd` accepts the certificate only for the accounts it lists.

use std::{fs::OpenOptions, io::Write, path::Path};

use clap::{Args, Subcommand};
use cosmian_kms_client::{
    KmsClient, kmip_2_1::requests::create_ec_key_pair_request,
    reexport::cosmian_kms_client_utils::create_utils::Curve, restrict_to_owner,
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
};
use serde::{Deserialize, Serialize};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use zeroize::Zeroizing;

use crate::{
    actions::console::Stdout,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Manage the SSH certificate authority and issue OpenSSH user certificates.
///
/// Typical flow (Crypto Officer): `ca create`, `role put`; then any role user: `sign`.
#[derive(Subcommand, Debug)]
pub enum SshCommands {
    /// Create or select the CA key, and read its public key.
    #[command(subcommand)]
    Ca(CaCommands),
    /// Define the signing roles (policies) users can request certificates with.
    #[command(subcommand)]
    Role(RoleCommands),
    /// Sign an OpenSSH user certificate with a configured KMS SSH CA.
    Sign(SignAction),
}

impl SshCommands {
    /// Run the selected `ssh` sub-command.
    ///
    /// # Errors
    /// Returns an error if the arguments are invalid or the server request fails.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Ca(command) => command.process(kms_rest_client).await,
            Self::Role(command) => command.process(kms_rest_client).await,
            Self::Sign(action) => action.run(kms_rest_client).await,
        }
    }
}

/// CA management: requires an active Crypto Officer.
#[derive(Subcommand, Debug)]
pub enum CaCommands {
    Create(CaCreateAction),
    Set(CaSetAction),
    PublicKey(CaPublicKeyAction),
}

impl CaCommands {
    async fn process(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Create(action) => action.run(kms_rest_client).await,
            Self::Set(action) => action.run(kms_rest_client).await,
            Self::PublicKey(action) => action.run(kms_rest_client).await,
        }
    }
}

/// Role management: requires an active Crypto Officer.
#[derive(Subcommand, Debug)]
pub enum RoleCommands {
    Put(RolePutAction),
}

impl RoleCommands {
    async fn process(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Put(action) => action.run(kms_rest_client).await,
        }
    }
}

#[derive(Serialize)]
struct ConfigureCaRequest<'a> {
    ca_key_uid: &'a str,
}

async fn configure_ca(kms_rest_client: &KmsClient, key_uid: &str) -> KmsCliResult<()> {
    kms_rest_client
        .put_no_content(
            "/v1/ssh/config/ca",
            &ConfigureCaRequest {
                ca_key_uid: key_uid,
            },
        )
        .await
        .context("configuring the SSH CA")?;
    Ok(())
}

async fn fetch_ca_public_key(kms_rest_client: &KmsClient) -> KmsCliResult<String> {
    let bytes = kms_rest_client
        .get_bytes("/v1/ssh/public_key", None::<&()>)
        .await
        .context("retrieving the SSH CA public key")?;
    String::from_utf8(bytes).context("the SSH CA public key is not valid UTF-8")
}

/// Create a new CA key pair in the KMS and make it the SSH CA.
///
/// The key pair is an elliptic-curve key pair (NIST P-256 by default). Replacing the CA
/// invalidates trust in certificates signed by the previous one on hosts that trust only the
/// new public key.
#[derive(Args, Debug)]
pub struct CaCreateAction {
    /// The elliptic curve of the CA key: an SSH CA accepts NIST P-256, P-384 and P-521, and
    /// Ed25519 in non-FIPS mode.
    #[clap(long = "curve", short = 'c', default_value = "nist-p256")]
    pub curve: Curve,

    /// Tag to associate with the CA key pair; repeat the option for several tags.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// Unique id of the CA private key; a random uuid is generated if not specified.
    pub private_key_id: Option<String>,

    /// Sensitive: if set, the private key will not be exportable. Required for an HSM key
    /// (`hsm::` id).
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,
}

impl CaCreateAction {
    async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        // Refuse curves the SSH CA rejects before creating a key pair that would be left unused.
        match self.curve {
            Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {}
            #[cfg(feature = "non-fips")]
            Curve::Ed25519 => {}
            #[cfg(feature = "non-fips")]
            Curve::X25519
            | Curve::X448
            | Curve::Ed448
            | Curve::Secp256k1
            | Curve::Secp192k1
            | Curve::Secp224k1 => {
                cli_bail!("an SSH CA key must use NIST P-256, P-384, P-521 or Ed25519")
            }
        }
        let private_key_id = self.private_key_id.as_ref().map(|id| {
            cosmian_kms_client::kmip_2_1::kmip_types::UniqueIdentifier::TextString(id.clone())
        });
        let request = create_ec_key_pair_request(
            kms_rest_client.config.vendor_id.as_str(),
            private_key_id,
            &self.tags,
            self.curve.into(),
            self.sensitive,
            None,
        )?;
        let response = kms_rest_client
            .create_key_pair(request)
            .await
            .context("creating the SSH CA key pair")?;
        let key_uid = response
            .private_key_unique_identifier
            .as_str()
            .context("the server did not return a private key id as a string")?
            .to_owned();
        configure_ca(kms_rest_client, &key_uid)
            .await
            .with_context(|| {
                format!("the key pair {key_uid} was created but not set as the SSH CA")
            })?;
        let public_key = fetch_ca_public_key(kms_rest_client).await?;
        Stdout::new(&format!(
            "SSH CA key pair created and configured; private key id: {key_uid}\n{}",
            public_key.trim_end()
        ))
        .write()
    }
}

/// Use an existing KMS key as the SSH CA.
///
/// You must own the key: its `Sign` right is delegated to the SSH signing authority, so role
/// users get certificates without any right on the key itself.
#[derive(Args, Debug)]
pub struct CaSetAction {
    /// Unique id of the CA private key.
    pub key_id: String,
}

impl CaSetAction {
    async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        configure_ca(kms_rest_client, &self.key_id).await?;
        let public_key = fetch_ca_public_key(kms_rest_client).await?;
        Stdout::new(&format!(
            "SSH CA configured with key {}\n{}",
            self.key_id,
            public_key.trim_end()
        ))
        .write()
    }
}

/// Print the CA public key in OpenSSH format, ready for `TrustedUserCAKeys` on SSH servers.
/// Needs no authentication on the SSH endpoint beyond access to the KMS.
#[derive(Args, Debug)]
pub struct CaPublicKeyAction;

impl CaPublicKeyAction {
    async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let public_key = fetch_ca_public_key(kms_rest_client).await?;
        Stdout::new(public_key.trim_end()).write()
    }
}

/// Create or replace a signing role.
///
/// A role limits which principals can be certified, for how long, and which KMS users may use
/// it. Active Crypto Officers can always use every role.
#[derive(Args, Debug)]
pub struct RolePutAction {
    /// Role name: 1 to 64 characters among letters, digits, `_`, `.` and `-`.
    pub name: String,

    /// Principal (e.g. a login name) certificates of this role may carry; repeatable.
    #[clap(long = "allowed-principal", required = true, num_args = 1..)]
    pub allowed_principals: Vec<String>,

    /// Certificate lifetime when `sign` gets no `--ttl`, such as `15m`.
    #[clap(long, default_value = "15m")]
    pub default_ttl: String,

    /// Longest certificate lifetime a user may request, such as `1h`.
    #[clap(long, default_value = "1h")]
    pub max_ttl: String,

    /// KMS user allowed to request certificates with this role; repeatable. Without any,
    /// only Crypto Officers can use the role.
    #[clap(long = "allowed-user", num_args = 1..)]
    pub allowed_users: Vec<String>,
}

#[derive(Serialize)]
struct PutRoleRequest<'a> {
    allowed_principals: &'a [String],
    default_ttl: &'a str,
    max_ttl: &'a str,
    allowed_users: &'a [String],
}

impl RolePutAction {
    async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        validate_role_name(&self.name)?;
        kms_rest_client
            .put_no_content(
                &format!("/v1/ssh/roles/{}", self.name),
                &PutRoleRequest {
                    allowed_principals: &self.allowed_principals,
                    default_ttl: &self.default_ttl,
                    max_ttl: &self.max_ttl,
                    allowed_users: &self.allowed_users,
                },
            )
            .await
            .context("saving the SSH role")?;
        Stdout::new(&format!("SSH role '{}' saved.", self.name)).write()
    }
}

/// The server accepts `[A-Za-z0-9_.-]`, 1 to 64 characters; checking here keeps the name from
/// altering the request path.
fn validate_role_name(name: &str) -> KmsCliResult<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        cli_bail!("invalid role name '{name}': use 1 to 64 letters, digits, '_', '.' or '-'");
    }
    Ok(())
}

/// Request an OpenSSH user certificate for `ROLE`.
///
/// Certify an existing public key, or let `--generate-key` create a new ECDSA P-256 key pair
/// locally; its private key never reaches the KMS. Principals are the names written in the
/// certificate (login names for a user certificate): `sshd` accepts the certificate for an
/// account only if the account's principals include one of them. They must be allowed by the
/// role.
#[derive(Args, Debug)]
pub struct SignAction {
    /// SSH signing role (see `ckms ssh role put`).
    pub role: String,

    /// OpenSSH public key to certify, as text (e.g. `"$(cat ~/.ssh/id_ed25519.pub)"`).
    #[clap(
        required_unless_present = "generate_key",
        conflicts_with = "generate_key"
    )]
    pub public_key: Option<String>,

    /// Generate a new key pair instead: writes the private key to PATH (mode 0600), the public
    /// key to PATH.pub and the certificate to PATH-cert.pub. Existing files are not overwritten.
    #[clap(long, value_name = "PATH")]
    pub generate_key: Option<String>,

    /// Principal embedded in the certificate: the login name (or host name) it is valid for.
    /// Repeatable; every principal must be allowed by the role.
    #[clap(long = "principal", short = 'p', required = true, num_args = 1..)]
    pub valid_principals: Vec<String>,

    /// Certificate lifetime, such as `15m`; defaults to the role's default and cannot exceed
    /// its maximum.
    #[clap(long)]
    pub ttl: Option<String>,
}

#[derive(Serialize)]
struct SignRequest<'a> {
    public_key: &'a str,
    valid_principals: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
}

#[derive(Deserialize)]
struct SignResponse {
    data: SignedKeyData,
}

#[derive(Deserialize)]
struct SignedKeyData {
    signed_key: String,
}

/// Create a new file: an existing one is never overwritten, and a private key is readable by
/// its owner only.
fn write_new_file(path: &Path, contents: &[u8], private: bool) -> KmsCliResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    restrict_to_owner(&mut options, private);
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))
}

/// A new ECDSA P-256 key pair: the private key as a PEM (accepted by `ssh -i`) and the public
/// key in OpenSSH format.
fn generate_subject_key() -> KmsCliResult<(Zeroizing<Vec<u8>>, String)> {
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("loading the P-256 curve")?;
    let key = EcKey::generate(&group).context("generating the SSH key pair")?;
    let private_pem = Zeroizing::new(
        key.private_key_to_pem()
            .context("encoding the SSH private key")?,
    );
    let mut ctx = BigNumContext::new().context("allocating a big-number context")?;
    let point = key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .context("encoding the SSH public key")?;
    let public = ssh_key::PublicKey::from(KeyData::Ecdsa(
        EcdsaPublicKey::from_sec1_bytes(&point).context("encoding the SSH public key")?,
    ));
    let openssh = public.to_openssh().context("encoding the SSH public key")?;
    Ok((private_pem, openssh))
}

impl SignAction {
    async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        validate_role_name(&self.role)?;
        let generated = match &self.generate_key {
            Some(path) => {
                let path = Path::new(path);
                let pub_path = format!("{}.pub", path.display());
                let cert_path = format!("{}-cert.pub", path.display());
                for existing in [
                    path.display().to_string(),
                    pub_path.clone(),
                    cert_path.clone(),
                ] {
                    if Path::new(&existing).exists() {
                        cli_bail!("{existing} already exists; it is not overwritten");
                    }
                }
                let (private_pem, public_key) = generate_subject_key()?;
                Some((path, pub_path, cert_path, private_pem, public_key))
            }
            None => None,
        };
        let Some(public_key) = generated
            .as_ref()
            .map(|(.., public_key)| public_key.as_str())
            .or(self.public_key.as_deref())
        else {
            cli_bail!("provide a public key or --generate-key")
        };
        let response: SignResponse = kms_rest_client
            .post_no_ttlv(
                &format!("/v1/ssh/sign/{}", self.role),
                Some(&SignRequest {
                    public_key,
                    valid_principals: &self.valid_principals,
                    ttl: self.ttl.as_deref(),
                }),
            )
            .await?;
        let Some((path, pub_path, cert_path, private_pem, public_key)) = generated else {
            return Stdout::new(&response.data.signed_key).write();
        };
        write_new_file(path, &private_pem, true)?;
        write_new_file(
            Path::new(&pub_path),
            format!("{public_key}\n").as_bytes(),
            false,
        )?;
        write_new_file(
            Path::new(&cert_path),
            format!("{}\n", response.data.signed_key.trim_end()).as_bytes(),
            false,
        )?;
        Stdout::new(&format!(
            "Private key: {}\nPublic key: {pub_path}\nCertificate: {cert_path}",
            path.display()
        ))
        .write()
    }
}

/// Generate a fresh 32-character password using KMS-managed randomness.
#[derive(Args, Debug)]
pub struct PasswordAction;

#[derive(Deserialize)]
struct PasswordResponse {
    data: PasswordData,
}

#[derive(Deserialize)]
struct PasswordData {
    password: String,
}

impl PasswordAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response: PasswordResponse = kms_rest_client
            .post_no_ttlv("/v1/secrets/password", Some(&serde_json::json!({})))
            .await
            .context("generating password")?;
        Stdout::new(&response.data.password).write()
    }
}
