use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use abe_policy::{AccessPolicy, Attribute};
use clap::StructOpt;
use cosmian_kmip::kmip::kmip_operations::Get;
use cosmian_kms_client::{kmip::kmip_types::RevocationReason, KmsRestClient};
use cosmian_kms_utils::{
    crypto::{
        cover_crypt::kmip_requests::{
            build_create_master_keypair_request as cc_build_create_master_keypair_request,
            build_create_user_decryption_private_key_request as cc_build_create_user_decryption_private_key_request,
            build_destroy_key_request as cc_build_destroy_key_request,
            build_import_decryption_private_key_request as cc_build_import_decryption_private_key_request,
            build_import_private_key_request as cc_build_import_private_key_request,
            build_import_public_key_request as cc_build_import_public_key_request,
            build_rekey_keypair_request as cc_build_rekey_keypair_request,
            build_revoke_user_decryption_key_request as cc_build_revoke_user_decryption_key_request,
        },
        gpsw::kmip_requests::{
            build_create_master_keypair_request as abe_build_create_master_keypair_request,
            build_create_user_decryption_private_key_request as abe_build_create_user_decryption_private_key_request,
            build_destroy_key_request as abe_build_destroy_key_request,
            build_import_decryption_private_key_request as abe_build_import_decryption_private_key_request,
            build_import_private_key_request as abe_build_import_private_key_request,
            build_import_public_key_request as abe_build_import_public_key_request,
            build_rekey_keypair_request as abe_build_rekey_keypair_request,
            build_revoke_user_decryption_key_request as abe_build_revoke_user_decryption_key_request,
        },
    },
    kmip_utils::unwrap_key_bytes,
};
use eyre::Context;
use uuid::Uuid;

/// Create a new master access key pair for a given policy.
/// The master public key is used to encrypt the files and can be safely shared.
/// The master secret key is used to generate user decryption keys and must be
/// kept confidential.
/// Both of them are stored inside the KMS.
/// This command returns a couple of ID refering to this new key pair.
#[derive(StructOpt, Debug)]
pub struct NewMasterKeyPairAction {
    /// The policy filename. The policy is expressed as a JSON object
    /// describing the Policy axes and attributes. See the documentation for
    /// details.
    #[structopt(
        required = false,
        long = "policy",
        short = 'p',
        parse(from_os_str),
        default_value = "policy.json"
    )]
    policy_file: PathBuf,
}

impl NewMasterKeyPairAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Parse the json policy file
        let policy = super::policy::policy_from_file(&self.policy_file)?;

        // Create the kmip query
        let create_key_pair = if is_cover_crypt {
            cc_build_create_master_keypair_request(&policy)?
        } else {
            abe_build_create_master_keypair_request(&policy)?
        };

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = client_connector
            .create_key_pair(create_key_pair)
            .await
            .with_context(|| "Can't connect to the kms server")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;

        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        println!("The master key pair has been properly generated.");
        println!("Store the followings securely for any further uses:\n");
        println!("  Private key unique identifier: {private_key_unique_identifier}");
        println!("\n  Public key unique identifier: {public_key_unique_identifier}");

        Ok(())
    }
}

/// Generate a new user decryption key given an Access Policy expressed
/// as a boolean expression. The user decryption key can decrypt files with
/// attributes matching its access policy (i.e. the access policy is true).
///
/// Example: cosmian_kms_cli cc new -s abf0e213-59c1-4acf-bb93-8ab4bedfa2f5 "department::marketing && level::secret"
#[derive(StructOpt, Debug)]
pub struct NewUserKeyAction {
    /// The private master key unique identifier stored in the KMS
    #[structopt(required = true, long = "secret-key-id", short = 's')]
    secret_key_id: String,

    /// The access policy is a boolean expression combining policy attributes.
    /// Example: `(department::marketing || department::finance) && level::secret`
    #[structopt(required = true)]
    access_policy: String,
}

impl NewUserKeyAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Parse self.access_policy
        let policy = if self.access_policy.trim().is_empty() {
            AccessPolicy::All
        } else {
            AccessPolicy::from_boolean_expression(&self.access_policy)
                .with_context(|| "Bad access policy definition")?
        };

        // Create the kmip query
        let create_user_key = if is_cover_crypt {
            cc_build_create_user_decryption_private_key_request(&policy, &self.secret_key_id)?
        } else {
            abe_build_create_user_decryption_private_key_request(&policy, &self.secret_key_id)?
        };

        // Query the KMS with your kmip data
        let create_response = client_connector
            .create(create_user_key)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let user_key_unique_identifier = &create_response.unique_identifier;

        println!("The decryption user key has been properly generated.");
        println!("Store the followings securely for any further uses:");
        println!("\n  Decryption user key unique identifier: {user_key_unique_identifier}");

        Ok(())
    }
}

/// Revoke a user decryption key.
#[derive(StructOpt, Debug)]
pub struct RevokeUserKeyAction {
    /// The user decryption key unique identifier stored in the KMS
    /// to revoke
    #[structopt(required = true, long = "user-key-id", short = 'u')]
    user_key_id: String,

    /// The reason of this revocation
    #[structopt(required = true, long = "revocation-reason", short = 'r')]
    revocation_reason: String,
    // /// Compromission date if it occurs
    // #[structopt(long = "compromission-date", short = "d")]
    // compromise_occurrence_date: Option<String>,
}

impl RevokeUserKeyAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Create the kmip query
        let revoke_query = if is_cover_crypt {
            cc_build_revoke_user_decryption_key_request(
                &self.user_key_id,
                RevocationReason::TextString(self.revocation_reason.to_owned()),
            )?
        } else {
            abe_build_revoke_user_decryption_key_request(
                &self.user_key_id,
                RevocationReason::TextString(self.revocation_reason.to_owned()),
            )?
        };

        // Query the KMS with your kmip data
        let revoke_response = client_connector
            .revoke(revoke_query)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if self.user_key_id == revoke_response.unique_identifier {
            println!("The decryption user key has been properly revoked.");
            Ok(())
        } else {
            eyre::bail!("Something went wrong when revoking the user key.")
        }
    }
}

/// Rotate an attribute and update the master public key file.
/// New files encrypted with the rotated attribute
/// cannot be decrypted by user decryption keys until they have been re-keyed.
#[derive(StructOpt, Debug)]
pub struct RotateAttributeAction {
    /// The private master key unique identifier stored in the KMS
    #[structopt(required = true, long = "secret-key-id", short = 's')]
    secret_key_id: String,

    /// The policy attributes to rotate.
    /// Example: `-a department::marketing -a level::confidential`
    #[structopt(required = true, long, short)]
    attributes: Vec<String>,
}

impl RotateAttributeAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Parse the attributes
        let attributes = self
            .attributes
            .iter()
            .map(|s| Attribute::try_from(s.as_str()).map_err(Into::into))
            .collect::<eyre::Result<Vec<Attribute>>>()?;

        // Create the kmip query
        let rotate_query = if is_cover_crypt {
            cc_build_rekey_keypair_request(&self.secret_key_id, attributes)?
        } else {
            abe_build_rekey_keypair_request(&self.secret_key_id, attributes)?
        };

        // Query the KMS with your kmip data
        let rotate_response = client_connector
            .rekey_keypair(rotate_query)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if self.secret_key_id == rotate_response.private_key_unique_identifier {
            println!("The master key pair has been properly rotated.");
            Ok(())
        } else {
            eyre::bail!("Something went wrong when rotating the user key.")
        }
    }
}

/// Destroy the decryption key for a given user.
#[derive(StructOpt, Debug)]
pub struct DestroyUserKeyAction {
    /// The user decryption key unique identifier stored in the KMS
    /// to destroy
    #[structopt(required = true, long = "user-key-id", short = 'u')]
    user_key_id: String,
}

impl DestroyUserKeyAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Create the kmip query
        let destroy_query = if is_cover_crypt {
            cc_build_destroy_key_request(&self.user_key_id)?
        } else {
            abe_build_destroy_key_request(&self.user_key_id)?
        };

        // Query the KMS with your kmip data
        let destroy_response = client_connector
            .destroy(destroy_query)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if self.user_key_id == destroy_response.unique_identifier {
            println!("The decryption user key has been properly destroyed.");
            Ok(())
        } else {
            eyre::bail!("Something went wrong when destroying the user key.")
        }
    }
}

/// Import (wrapped, to wrap or unwrapped) ABE raw keys for a given user.
/// Note: the keys import must be in raw format.
/// If you want to import keys serialized in TTLV format, please use `import` subcommand.
#[derive(StructOpt, Debug)]
pub struct ImportKeysAction {
    /// The private master key file (hint: raw binary file) (to set if `public-key-file` is set). [Wrappable]
    #[structopt(
        name = "secret_key_file",
        required_unless_present = "user_key_file",
        requires_all = &["public_key_file", "policy"],
        long = "secret-key-file",
        short = 'S',
        parse(from_os_str)
    )]
    secret_key_file: Option<PathBuf>,

    /// The public master key file (hint: raw binary file) (to set if `secret-key-file` is set). [Not wrappable].
    #[structopt(
        name = "public_key_file",
        required_unless_present = "user_key_file",
        requires_all = &["secret_key_file", "policy"],
        long = "public-key-file",
        short = 'P',
        parse(from_os_str)
    )]
    public_key_file: Option<PathBuf>,

    /// The policy filename. The policy is expressed as a JSON object
    /// describing the Policy axes and attributes.
    /// See the documentation for details.
    #[structopt(
        name = "policy",
        required_unless_present = "user_key_file",
        requires_all = &["secret_key_file", "public_key_file"],
        long = "policy",
        short = 'p',
        parse(from_os_str)
    )]
    policy_file: Option<PathBuf>,

    /// The user decryption key file (hint: raw binary file) (can't be set if `secret-key-file`/`public-key-file` are set). [Wrappable]
    #[structopt(
        name = "user_key_file",
        required_unless_present_any = ["secret_key_file", "public_key_file"],
        requires_all = &["access_policy", "secret_key_id"],
        long = "user-key-file",
        short = 'U',
        parse(from_os_str)
    )]
    user_key_file: Option<PathBuf>,

    /// The access policy is a boolean expression combining policy attributes.
    /// Example: `(department::marketing || department::finance) && level::secret`
    #[structopt(
        required_unless_present_any = ["secret_key_file", "public_key_file"],
        requires_all = &["user_key_file", "secret_key_id"],
        name = "access_policy",
        long = "access-policy",
        short = 'a'
    )]
    access_policy: Option<String>,

    /// The private master key unique identifier stored in the KMS linked to the user decryption key
    #[structopt(
        required_unless_present_any = ["secret_key_file", "public_key_file"],
        requires_all = &["user_key_file", "access_policy"],
        name = "secret_key_id",
        long = "secret-key-id",
        short = 's'
    )]
    secret_key_id: Option<String>,

    /// Wrap the key (if [Wrappable]) using a password before importing it
    #[structopt(required = false, long, short = 'W')]
    password: Option<String>,

    /// The provided key is already wrapped. If false, it is imported in plain text. Is ignored if password is set.
    #[structopt(long = "wrapped", short = 'w')]
    wrapped: bool,
}

impl ImportKeysAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        match (
            &self.secret_key_file,
            &self.public_key_file,
            &self.policy_file,
            &self.user_key_file,
            &self.secret_key_id,
            &self.access_policy,
        ) {
            (Some(secret_key_file), Some(public_key_file), Some(policy_file), None, None, None) => {
                // Parse the json policy file
                let policy = super::policy::policy_from_file(policy_file)?;

                // Read the private key
                let mut f = File::open(&secret_key_file)
                    .with_context(|| "Can't read the private key file")?;
                let mut private_key = Vec::new();
                f.read_to_end(&mut private_key)
                    .with_context(|| "Fail to read the private key file")?;

                // Read the public key
                let mut f = File::open(&public_key_file)
                    .with_context(|| "Can't read the public key file")?;
                let mut public_key = Vec::new();
                f.read_to_end(&mut public_key)
                    .with_context(|| "Fail to read the public key file")?;

                // We force the uuid to be able to share them between the two objects: public and private keys
                let private_uuid = Uuid::new_v4().to_string();
                let public_uuid = Uuid::new_v4().to_string();

                // Create the kmip query for private key
                let import_private_query = if is_cover_crypt {
                    cc_build_import_private_key_request(
                        &private_key,
                        Some(private_uuid),
                        false,
                        &public_uuid,
                        &policy,
                        self.wrapped,
                        self.password.clone(),
                    )?
                } else {
                    abe_build_import_private_key_request(
                        &private_key,
                        Some(private_uuid),
                        false,
                        &public_uuid,
                        &policy,
                        self.wrapped,
                        self.password.clone(),
                    )?
                };

                // Query the KMS with your kmip data for private key
                let import_private_response =
                    client_connector
                        .import(import_private_query)
                        .await
                        .with_context(|| "Can't execute the query on the kms server")?;

                let private_key_unique_identifier = &import_private_response.unique_identifier;

                // Create the kmip query for public key

                let import_public_query = if is_cover_crypt {
                    cc_build_import_public_key_request(
                        &public_key,
                        Some(public_uuid),
                        false,
                        &policy,
                        private_key_unique_identifier,
                    )?
                } else {
                    abe_build_import_public_key_request(
                        &public_key,
                        Some(public_uuid),
                        false,
                        &policy,
                        private_key_unique_identifier,
                    )?
                };

                // Query the KMS with your kmip data for public key
                let import_public_response = client_connector
                    .import(import_public_query)
                    .await
                    .with_context(|| "Can't execute the query on the kms server")?;

                let public_key_unique_identifier = &import_public_response.unique_identifier;

                println!("The master key pair has been properly imported.");
                println!("Store the followings securely for any further uses:\n");
                println!("  Private key unique identifier: {private_key_unique_identifier}");
                println!("\n  Public key unique identifier: {public_key_unique_identifier}");
            }
            (None, None, None, Some(user_key_file), Some(secret_key_id), Some(access_policy)) => {
                // Read the public key
                let mut f =
                    File::open(&user_key_file).with_context(|| "Can't read the user key file")?;
                let mut user_key = Vec::new();
                f.read_to_end(&mut user_key)
                    .with_context(|| "Fail to read the user key file")?;

                let policy = if access_policy.trim().is_empty() {
                    AccessPolicy::All
                } else {
                    AccessPolicy::from_boolean_expression(access_policy)
                        .with_context(|| "Bad access policy definition")?
                };

                let import_query = if is_cover_crypt {
                    // Create the kmip query
                    cc_build_import_decryption_private_key_request(
                        &user_key,
                        None,
                        false,
                        secret_key_id,
                        &policy,
                        self.wrapped,
                        self.password.clone(),
                    )?
                } else {
                    // Create the kmip query
                    abe_build_import_decryption_private_key_request(
                        &user_key,
                        None,
                        false,
                        secret_key_id,
                        &policy,
                        self.wrapped,
                        self.password.clone(),
                    )?
                };

                // Query the KMS with your kmip data
                let import_response = client_connector
                    .import(import_query)
                    .await
                    .with_context(|| "Can't execute the query on the kms server")?;

                let user_key_unique_identifier = &import_response.unique_identifier;

                println!("The decryption user key has been properly imported.");
                println!("Store the followings securely for any further uses:");
                println!("\n  Decryption user key unique identifier: {user_key_unique_identifier}");
            }
            _ => {
                eyre::bail!(
                    "Wrong parameters: you should specify (secret_key_file, public_key_file and \
                     policy_file) or (user_key_file, secret_key_id, access_policy)."
                )
            }
        }

        Ok(())
    }
}

/// Export a key by its id.
/// Note: the exported key is in raw format.
/// If you want to export a key serialized in TTLV format, please use `export` subcommand
#[derive(StructOpt, Debug)]
pub struct ExportKeysAction {
    /// The output file to write the key
    #[structopt(required = true, name = "FILE", parse(from_os_str))]
    output_file: PathBuf,

    /// The key unique identifier stored in the KMS
    #[structopt(required = true, long = "key-id", short = 'k')]
    key_id: String,

    /// Unwrap the key using a password before writting it
    #[structopt(required = false, long, short = 'W')]
    password: Option<String>,
}

impl ExportKeysAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Query the KMS with your kmip data and get the key pair ids
        let get_response = client_connector
            .get(Get::from(&self.key_id))
            .await
            .with_context(|| "Can't connect to the kms server")?;

        let key = get_response.object.key_block()?.as_bytes()?;
        let key = if let Some(password) = &self.password {
            unwrap_key_bytes(key, password)?
        } else {
            key.to_vec()
        };

        // Write the key file
        let mut buffer =
            File::create(&self.output_file).with_context(|| "Fail to write the key file")?;
        buffer
            .write_all(&key)
            .with_context(|| "Fail to write the key file")?;

        println!("The key has been properly exported.");
        println!(
            "The key file can be found at {}",
            &self
                .output_file
                .to_str()
                .ok_or_else(|| eyre::eyre!("Could not display the name of key file"))?
        );

        Ok(())
    }
}
