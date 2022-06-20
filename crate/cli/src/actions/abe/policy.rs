use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use abe_gpsw::core::policy::Policy as AbePolicy;
use cover_crypt::policies::{Policy as CoverCryptPolicy, PolicyAxis as CoverCryptPolicyAxis};
use eyre::Context;
use serde::{Deserialize, Serialize};

/// Example of a json:
/// {
///    "policy": {
///            "level": {
///                    "hierarchical": true,
///                    "attributes": ["confidential","secret","top-secret"]
///            },
///            "department": {
///                    "hierarchical": false,
///                    "attributes": ["finance","marketing","operations"]
///            }
///    },
///    "max-rotations": 100
/// }

#[derive(Serialize, Deserialize)]
struct InputPolicy {
    #[serde(alias = "max-rotations")]
    max_rotations: usize,
    #[serde(alias = "policy")]
    policy_axis: HashMap<String, InputPolicyAxis>,
}

#[derive(Serialize, Deserialize)]
struct InputPolicyAxis {
    hierarchical: bool,
    attributes: Vec<String>,
}

pub enum CLIPolicy {
    Abe(AbePolicy),
    CoverCrypt(CoverCryptPolicy),
}

pub fn policy_from_file(
    json_filename: &impl AsRef<Path>,
    is_cover_crypt: bool,
) -> eyre::Result<CLIPolicy> {
    let file = File::open(json_filename).with_context(|| "Can't read the policy json file")?;

    // Read the json
    let raw_policy: InputPolicy =
        serde_json::from_reader(BufReader::new(file)).with_context(|| "Policy JSON malformed")?;

    // Build the policy
    let mut policy: CLIPolicy = if is_cover_crypt {
        CLIPolicy::CoverCrypt(CoverCryptPolicy::new(raw_policy.max_rotations as u32))
    } else {
        CLIPolicy::Abe(AbePolicy::new(raw_policy.max_rotations))
    };

    // Build the policy axis
    for (name, axis) in &raw_policy.policy_axis {
        let v = axis
            .attributes
            .iter()
            .map(|x| x.as_ref())
            .collect::<Vec<_>>();

        policy = match policy {
            CLIPolicy::Abe(p) => CLIPolicy::Abe(
                p.add_axis(name, &v, axis.hierarchical)
                    .with_context(|| format!("Can't initialize the policy axis {name}"))?,
            ),
            CLIPolicy::CoverCrypt(mut p) => {
                p.add_axis(&CoverCryptPolicyAxis::new(name, &v, axis.hierarchical))
                    .with_context(|| format!("Can't initialize the policy axis {name}"))?;
                CLIPolicy::CoverCrypt(p)
            }
        };
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::policy_from_file;

    #[test]
    pub fn test_policy_from_file() {
        //file not found
        let result = policy_from_file(&PathBuf::from("not_exist"), false);
        assert_eq!(
            result.err().unwrap().to_string(),
            "Can't read the policy json file"
        );

        // malformed json
        let result = policy_from_file(&PathBuf::from("test_data/policy.bad"), false);
        assert_eq!(result.err().unwrap().to_string(), "Policy JSON malformed");

        // duplicate policies
        let result = policy_from_file(&PathBuf::from("test_data/policy.bad2"), false);
        assert_eq!(
            result.err().unwrap().to_string(),
            "Can't initialize the policy axis level"
        );
    }
}
