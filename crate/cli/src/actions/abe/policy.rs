use std::{fs::File, io::Read, path::Path};

use cosmian_cover_crypt::abe_policy::Policy;
use eyre::Context;

pub fn policy_from_file(json_filename: &impl AsRef<Path>) -> eyre::Result<Policy> {
    let mut policy_str = String::new();
    File::open(json_filename)
        .with_context(|| {
            format!(
                "Could not open the file {}",
                json_filename.as_ref().display()
            )
        })?
        .read_to_string(&mut policy_str)
        .with_context(|| {
            format!(
                "Could not read the file {}",
                json_filename.as_ref().display()
            )
        })?;
    Policy::parse_and_convert(policy_str.as_bytes())
        .with_context(|| format!("Policy JSON malformed {}", json_filename.as_ref().display()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::policy_from_file;

    #[test]
    pub fn test_policy_from_file() {
        //file not found
        const WRONG_FILENAME: &str = "not_exist";
        let result = policy_from_file(&PathBuf::from(WRONG_FILENAME));
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("Could not open the file {WRONG_FILENAME}")
        );

        // malformed json
        const MALFORMED_FILE: &str = "test_data/policy.bad";
        let result = policy_from_file(&PathBuf::from(MALFORMED_FILE));
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("Policy JSON malformed {MALFORMED_FILE}")
        );

        // duplicate policies
        const DUPLICATED_POLICIES: &str = "test_data/policy.bad2";
        let result = policy_from_file(&PathBuf::from(DUPLICATED_POLICIES));
        assert_eq!(
            result.err().unwrap().to_string(),
            format!("Policy JSON malformed {DUPLICATED_POLICIES}")
        );
    }
}
