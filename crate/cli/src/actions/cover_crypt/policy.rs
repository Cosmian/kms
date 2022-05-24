use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use cover_crypt::policies::{Policy, PolicyAxis};
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
    max_rotations: u32,
    #[serde(alias = "policy")]
    policy_axis: HashMap<String, InputPolicyAxis>,
}

#[derive(Serialize, Deserialize)]
struct InputPolicyAxis {
    hierarchical: bool,
    attributes: Vec<String>,
}

pub fn policy_from_file(json_filename: &impl AsRef<Path>) -> eyre::Result<Policy> {
    let file =
        File::open(json_filename).with_context(|| "Can't read the policy json file".to_string())?;

    // Read the json
    let raw_policy: InputPolicy = serde_json::from_reader(BufReader::new(file))
        .with_context(|| "Policy JSON malformed".to_string())?;

    // Build the policy
    let mut policy = Policy::new(raw_policy.max_rotations);

    // Build the policy axis
    for (name, axis) in &raw_policy.policy_axis {
        let v: Vec<&str> = axis.attributes.iter().map(|x| x.as_ref()).collect();
        policy.add_axis(&PolicyAxis::new(name, &v, axis.hierarchical))?;
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
        let result = policy_from_file(&PathBuf::from("not_exist"));
        assert_eq!(
            result.err().unwrap().to_string(),
            "Can't read the policy json file"
        );

        // malformed json
        let result = policy_from_file(&PathBuf::from("test_data/policy.bad"));
        assert_eq!(result.err().unwrap().to_string(), "Policy JSON malformed");

        // duplicate policies
        let result = policy_from_file(&PathBuf::from("test_data/policy.bad2"));
        assert_eq!(
            result.err().unwrap().to_string(),
            "policy level already exists"
        );
    }
}
