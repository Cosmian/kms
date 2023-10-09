use clap::Parser;

use crate::{config::CliConf, error::CliError};

/// Logout from the Identity Provider.
///
/// The access token will be removed from the ckms configuration file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LogoutAction;

impl LogoutAction {
    pub async fn process(&self) -> Result<(), CliError> {
        let conf_location = CliConf::location()?;
        let mut conf = CliConf::load()?;
        conf.kms_access_token = None;
        conf.save()?;

        println!(
            "\nThe access token was removed from the KMS configuration file: {:?}",
            conf_location
        );

        Ok(())
    }
}
