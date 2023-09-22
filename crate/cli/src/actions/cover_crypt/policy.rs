use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use cloudproof::reexport::cover_crypt::abe_policy::{
    Attribute, EncryptionHint, Policy, PolicyAxis,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    ttlv::{deserializer::from_ttlv, TTLV},
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::cover_crypt::attributes::policy_from_attributes;
use serde::{Deserialize, Serialize};

use crate::{
    actions::shared::utils::{
        export_object, read_bytes_from_file, read_from_json_file, write_json_object_to_file,
    },
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicySpecifications(HashMap<String, Vec<String>>);

impl PolicySpecifications {
    /// Create a `Policy` from `PolicySpecifications`
    pub fn to_policy(&self) -> Result<Policy, CliError> {
        let mut policy = Policy::new(u32::MAX);
        for (axis, attributes) in &self.0 {
            // Split the axis into axis name and hierarchy flag
            let (axis_name, hierarchical) = match axis.split_once("::") {
                Some((name, specs)) => {
                    // If the axis contains the hierarchy flag, parse it
                    let hierarchical = match specs {
                        "<" => true,
                        x => cli_bail!("unknown axis spec {}", x),
                    };
                    (name, hierarchical)
                }
                // If there is no hierarchy flag, assume the axis is non-hierarchical
                None => (axis.as_str(), false),
            };

            let mut attributes_properties: Vec<(&str, EncryptionHint)> =
                Vec::with_capacity(attributes.len());

            // Parse each attribute and its encryption hint
            for att in attributes {
                let (att_name, encryption_hint) = match att.split_once("::") {
                    Some((name, specs)) => {
                        let encryption_hint = match specs {
                            "+" => EncryptionHint::Hybridized,
                            x => cli_bail!("unknown attribute spec {}", x),
                        };
                        (name, encryption_hint)
                    }
                    // If there is no encryption hint, assume the attribute is non-hybridized
                    None => (att.as_str(), EncryptionHint::Classic),
                };
                attributes_properties.push((att_name, encryption_hint));
            }

            // Add the axis to the policy
            policy.add_axis(PolicyAxis::new(
                axis_name,
                attributes_properties,
                hierarchical,
            ))?;
        }
        Ok(policy)
    }

    /// Read a JSON policy specification from a file
    pub fn from_json_file(file: &impl AsRef<Path>) -> Result<Self, CliError> {
        read_from_json_file(file)
    }
}

impl TryInto<Policy> for PolicySpecifications {
    type Error = CliError;

    fn try_into(self) -> Result<Policy, Self::Error> {
        self.to_policy()
    }
}

impl TryFrom<&Policy> for PolicySpecifications {
    type Error = CliError;

    fn try_from(policy: &Policy) -> Result<Self, Self::Error> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        for (axis_name, params) in &policy.axes {
            let axis_full_name =
                axis_name.clone() + if params.is_hierarchical { "::+" } else { "" };
            let mut attributes = Vec::with_capacity(params.attribute_names.len());
            for att in &params.attribute_names {
                let name = att.clone()
                    + match policy.attribute_hybridization_hint(&Attribute::new(axis_name, att))? {
                        EncryptionHint::Hybridized => "::+",
                        EncryptionHint::Classic => "",
                    };
                attributes.push(name);
            }
            result.insert(axis_full_name, attributes);
        }
        Ok(Self(result))
    }
}

pub fn policy_from_binary_file(bin_filename: &impl AsRef<Path>) -> Result<Policy, CliError> {
    let policy_buffer = read_bytes_from_file(bin_filename)?;
    Policy::parse_and_convert(policy_buffer.as_slice()).with_context(|| {
        format!(
            "policy binary is malformed {}",
            bin_filename.as_ref().display()
        )
    })
}

pub fn policy_from_specifications_file(
    specs_filename: &impl AsRef<Path>,
) -> Result<Policy, CliError> {
    let policy_specs: PolicySpecifications = read_from_json_file(&specs_filename)?;
    policy_specs.to_policy()
}

/// Extract or view policies of existing keys,
/// and create a binary policy from specifications.
#[derive(Subcommand)]
pub enum PolicyCommands {
    View(ViewAction),
    Specs(SpecsAction),
    Binary(BinaryAction),
    Create(CreateAction),
}

impl PolicyCommands {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::View(action) => action.run(kms_rest_client).await?,
            Self::Specs(action) => action.run(kms_rest_client).await?,
            Self::Binary(action) => action.run(kms_rest_client).await?,
            Self::Create(action) => action.run().await?,
        };

        Ok(())
    }
}

/// Create a policy binary file from policy specifications
///
/// The policy specifications must be passed as a JSON in a file, for example:
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
/// These specifications create a policy where:
///  - the policy is defined with 2 policy axes: `Security Level` and `Department`
///  - the `Security Level` axis is hierarchical as indicated by the `::<` suffix,
///  - the `Security Level` axis has 3 possible values: `Protected`, `Confidential`, and `Top Secret`,
///  - the `Department` axis has 4 possible values: `R&D`, `HR`, `MKG`, and `FIN`,
///  - all partitions which are `Top Secret` will be encrypted using post-quantum hybridized cryptography, as indicated by the `::+` suffix on the value,
///  - all other partitions will use classic cryptography.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateAction {
    /// The policy specifications filename. The policy is expressed as a JSON object
    /// describing the Policy axes. See the documentation for
    /// details.
    #[clap(
        required = false,
        long = "specifications",
        short = 's',
        default_value = "policy_specifications.json"
    )]
    policy_specifications_file: PathBuf,

    /// The output binary policy file generated from the specifications file.
    #[clap(
        required = false,
        long = "policy",
        short = 'p',
        default_value = "policy.bin"
    )]
    policy_binary_file: PathBuf,
}

impl CreateAction {
    pub async fn run(&self) -> Result<(), CliError> {
        // Parse the json policy file
        let specs = PolicySpecifications::from_json_file(&self.policy_specifications_file)?;

        // create the policy
        let policy = specs.to_policy()?;

        // write the binary file
        write_json_object_to_file(&policy, &self.policy_binary_file)
            .with_context(|| "failed writing the policy binary file".to_string())?;

        println!(
            "The binary policy file was generated in {:?}.",
            &self.policy_binary_file
        );
        Ok(())
    }
}

/// Recover the Policy from a key store in the KMS or in a TTLV file
async fn recover_policy(
    key_id: Option<&str>,
    key_file: Option<&PathBuf>,
    unwrap: bool,
    kms_rest_client: &KmsRestClient,
) -> Result<Policy, CliError> {
    // Recover the KMIP Object
    let object: Object = if let Some(key_id) = key_id {
        export_object(kms_rest_client, key_id, unwrap, None, false).await?
    } else if let Some(f) = key_file {
        let ttlv: TTLV = read_from_json_file(f)?;
        from_ttlv(&ttlv)?
    } else {
        cli_bail!("either a key ID or a key TTLV file must be supplied");
    };
    // Recover the policy
    policy_from_attributes(object.attributes()?)
        .with_context(|| "failed recovering the policy from the key")
}

/// Extract the policy specifications from a public or private master key to a policy specifications file
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct SpecsAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in JSON TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// The output policy specifications file.
    #[clap(
        required = false,
        long = "specifications",
        short = 's',
        default_value = "policy_specifications.json"
    )]
    policy_specs_file: PathBuf,
}
impl SpecsAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        let specs = PolicySpecifications::try_from(&policy)?;
        // save the policy to the specifications file
        write_json_object_to_file(&specs, &self.policy_specs_file)
    }
}

/// Extract the policy from a public or private master key to a policy binary file
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct BinaryAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// The output binary policy file.
    #[clap(
        required = false,
        long = "policy",
        short = 'p',
        default_value = "policy.bin"
    )]
    policy_binary_file: PathBuf,
}
impl BinaryAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        // save the policy to the binary file
        write_json_object_to_file(&policy, &self.policy_binary_file)
    }
}

/// View the policy of an existing public or private master key.
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract rhe policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ViewAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// Show all the policy details rather than just the specifications
    #[clap(
        required = false,
        long = "detailed",
        short = 'd',
        default_value = "false"
    )]
    detailed: bool,
}
impl ViewAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        // get a pretty json and print it
        let json = if self.detailed {
            serde_json::to_string_pretty(&policy)?
        } else {
            let specs = PolicySpecifications::try_from(&policy)?;
            serde_json::to_string_pretty(&specs)?
        };
        println!("{json}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cloudproof::reexport::cover_crypt::abe_policy::{Attribute, EncryptionHint};

    use super::policy_from_binary_file;
    use crate::{actions::cover_crypt::policy::PolicySpecifications, error::CliError};

    #[test]
    pub fn test_policy_bin_from_file() {
        //correct
        const CORRECT_FILE: &str = "test_data/policy.bin";
        let result = policy_from_binary_file(&PathBuf::from(CORRECT_FILE));
        assert!(result.is_ok(), "The policy should be ok");

        //file not found
        const WRONG_FILENAME: &str = "not_exist";
        let result = policy_from_binary_file(&PathBuf::from(WRONG_FILENAME));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("could not open the file {WRONG_FILENAME}"))
        );

        // malformed json
        const MALFORMED_FILE: &str = "test_data/policy.bad";
        let result = policy_from_binary_file(&PathBuf::from(MALFORMED_FILE));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("policy binary is malformed {MALFORMED_FILE}"))
        );

        // duplicate policies
        const DUPLICATED_POLICIES: &str = "test_data/policy.bad2";
        let result = policy_from_binary_file(&PathBuf::from(DUPLICATED_POLICIES));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("policy binary is malformed {DUPLICATED_POLICIES}"))
        );
    }

    #[test]
    pub fn test_create_policy() -> Result<(), CliError> {
        let json = r#"
    {
        "Security Level::<": [
            "Protected",
            "Confidential",
            "Top Secret::+"
        ],
        "Department": [
            "R&D",
            "HR",
            "MKG",
            "FIN"
        ]
    }
    "#;

        let policy_json: PolicySpecifications = serde_json::from_str(json).unwrap();
        let policy = policy_json.to_policy()?;
        assert_eq!(policy.axes.len(), 2);
        assert!(policy.axes.get("Security Level").unwrap().is_hierarchical);
        assert!(!policy.axes.get("Department").unwrap().is_hierarchical);
        assert_eq!(
            policy
                .axes
                .get("Security Level")
                .unwrap()
                .attribute_names
                .len(),
            3
        );
        assert_eq!(
            policy
                .attribute_hybridization_hint(&Attribute::new("Department", "MKG"))
                .unwrap(),
            EncryptionHint::Classic
        );
        assert_eq!(
            policy
                .attribute_hybridization_hint(&Attribute::new("Security Level", "Protected"))
                .unwrap(),
            EncryptionHint::Classic
        );
        assert_eq!(
            policy
                .attribute_hybridization_hint(&Attribute::new("Security Level", "Top Secret"))
                .unwrap(),
            EncryptionHint::Hybridized
        );

        Ok(())
    }
}
