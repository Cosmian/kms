use std::{env, fs::File, io::BufReader};

use cosmian_kms_client::KmsRestClient;
use eyre::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CliConf {
    // Insecure is useful if the cli needs to connect to an HTTPS KMS using unsecured SSL certificate
    #[serde(default)]
    pub insecure: bool,
    pub kms_server_url: String,
    kms_access_token: String,
    pub kms_database_secret: Option<String>,
}

/// Define the configuration of the CLI reading a json
///
/// {
///     "insecure": false
///     "kms_server_url": "http://127.0.0.1:9998",
///     "kms_access_token": "AA...AAA"
///     "kms_database_secret": "BB...BBB"
/// }
///
pub const KMS_CLI_CONF_ENV: &str = "KMS_CLI_CONF";

impl CliConf {
    pub fn load() -> eyre::Result<KmsRestClient> {
        let cli_conf_filename =
            env::var(KMS_CLI_CONF_ENV).with_context(|| "Can't find KMS_CLI_CONF env variable")?;

        let file = File::open(&cli_conf_filename).with_context(|| {
            format!(
                "Can't read {} set in the KMS_CLI_CONF env variable",
                &cli_conf_filename
            )
        })?;

        let conf: CliConf = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("Config JSON malformed in {}", &cli_conf_filename))?;

        // Create a client to query the KMS
        let kms_connector = KmsRestClient::instantiate(
            &conf.kms_server_url,
            &conf.kms_access_token,
            conf.kms_database_secret.as_deref(),
            conf.insecure,
        )
        .with_context(|| {
            format!(
                "Can't build the query to connect to the kms server {}",
                &conf.kms_server_url
            )
        })?;

        Ok(kms_connector)
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::{CliConf, KMS_CLI_CONF_ENV};

    #[test]
    pub fn test_load() {
        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms.json");

        assert!(CliConf::load().is_ok());

        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms_partial.json");

        assert!(CliConf::load().is_ok());

        env::set_var(KMS_CLI_CONF_ENV, "not_exist.json");
        assert_eq!(
            CliConf::load().err().unwrap().to_string(),
            "Can't read not_exist.json set in the KMS_CLI_CONF env variable"
        );

        env::set_var(KMS_CLI_CONF_ENV, "test_data/kms.bad");
        assert_eq!(
            CliConf::load().err().unwrap().to_string(),
            "Config JSON malformed in test_data/kms.bad",
        );
    }
}
