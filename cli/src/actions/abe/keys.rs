use std::path::PathBuf;

use abe_gpsw::core::policy::{AccessPolicy, Attribute};
use clap::StructOpt;
use cosmian_kms_client::{kmip::kmip_types::RevocationReason, KmipRestClient};
use cosmian_kms_utils::crypto::abe::kmip_requests::{
    build_create_master_keypair_request, build_create_user_decryption_private_key_request,
    build_destroy_key_request, build_rekey_keypair_request,
    build_revoke_user_decryption_key_request,
};
use eyre::Context;

/// Create a new ABE master access key pair for a given policy.
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
    pub async fn run(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        // Parse the json policy file
        let policy = super::policy::policy_from_file(&self.policy_file)?;

        // Create the kmip query
        let create_key_pair = build_create_master_keypair_request(&policy)?;

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
#[derive(StructOpt, Debug)]
pub struct NewUserKeyAction {
    /// The private master key unique identifier stored in the KMS
    #[structopt(required = true, long = "secret-key-id", short = 's')]
    secret_key_id: String,

    /// The access policy is a boolean expression combining policy attributes.
    /// Example: `(department::marketing | department::finance) & level::secret`
    #[structopt(required = true)]
    access_policy: String,
}

impl NewUserKeyAction {
    pub async fn run(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        // Parse self.access_policy
        let policy = AccessPolicy::from_boolean_expression(&self.access_policy)
            .with_context(|| "Bad access policy definition")?;

        // Create the kmip query
        let create_user_key =
            build_create_user_decryption_private_key_request(&policy, &self.secret_key_id)?;

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
    /*
    /// Compromission date if it occurs
    #[structopt(long = "compromission-date", short = "d")]
    compromise_occurrence_date: Option<String>,
    */
}

impl RevokeUserKeyAction {
    pub async fn run(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        // Create the kmip query
        let revoke_query = build_revoke_user_decryption_key_request(
            &self.user_key_id,
            RevocationReason::TextString(self.revocation_reason.to_owned()),
        )?;

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
    #[structopt(required = true, short, long)]
    attributes: Vec<String>,
}

impl RotateAttributeAction {
    pub async fn run(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        // Parse the attributes
        let attributes = self
            .attributes
            .iter()
            .map(|s| Attribute::try_from(s.as_str()).map_err(Into::into))
            .collect::<eyre::Result<Vec<Attribute>>>()?;

        // Create the kmip query
        let rotate_query = build_rekey_keypair_request(&self.secret_key_id, attributes)?;

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
    pub async fn run(&self, client_connector: &KmipRestClient) -> eyre::Result<()> {
        // Create the kmip query
        let destroy_query = build_destroy_key_request(&self.user_key_id)?;

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
