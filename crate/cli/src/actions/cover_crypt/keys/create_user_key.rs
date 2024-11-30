use clap::Parser;
use cloudproof::reexport::cover_crypt::abe_policy::AccessPolicy;
use cosmian_kms_client::{
    cosmian_kmip::crypto::cover_crypt::kmip_requests::build_create_user_decryption_private_key_request,
    KmsClient,
};

use crate::{
    actions::console,
    error::result::{CliResult, CliResultHelper},
};

/// Create a new user decryption key given an access policy expressed as a boolean expression.
///
///
/// The access policy is a boolean expression over the attributes of the policy axis.
/// For example, for the policy below, the access policy expression
///
///    `Department::HR && Security Level::Confidential`
///
///    gives decryption access to all ciphertexts in the HR/Protected partition,
///    as well as those in the HR/Protected partition since the `Security Level` axis
///    is hierarchical.
///
/// A more complex access policy giving access to the 3 partitions MKG/Confidential,
/// MKG/Protected and HR/Protected would be
///
///    `(Department::MKG && Security Level::Confidential) || (Department::HR && Security Level::Protected)`
///
/// The policy used in these example is
/// ```json
///     {
///        "Security Level::<": [
///            "Protected",
///            "Confidential",
///            "Top Secret::+"
///        ],
///        "Department": [
///            "R&D",
///            "HR",
///            "MKG",
///            "FIN"
///        ]
///    }
/// ```
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct CreateUserKeyAction {
    /// The master private key unique identifier
    #[clap(required = true)]
    master_private_key_id: String,

    /// The access policy as a boolean expression combining policy attributes.
    ///
    /// Example: "(`Department::HR` || `Department::MKG`) && Security `Level::Confidential`"
    #[clap(required = true)]
    access_policy: String,

    /// The tag to associate with the user decryption key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    sensitive: bool,
}

impl CreateUserKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Verify boolean expression in self.access_policy
        AccessPolicy::from_boolean_expression(&self.access_policy)
            .with_context(|| "bad access policy syntax")?;

        // Create the kmip query
        let create_user_key = build_create_user_decryption_private_key_request(
            &self.access_policy,
            &self.master_private_key_id,
            &self.tags,
            self.sensitive,
        )?;

        // Query the KMS with your kmip data
        let create_response = kms_rest_client
            .create(create_user_key)
            .await
            .with_context(|| "user decryption key creation failed")?;

        let user_key_unique_identifier = &create_response.unique_identifier;

        let mut stdout =
            console::Stdout::new("The user decryption key pair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(user_key_unique_identifier.to_owned());
        stdout.write()?;

        Ok(())
    }
}
