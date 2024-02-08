use std::path::PathBuf;

use clap::Parser;

use crate::{config::CliConf, error::CliError};

/// Logout from the Identity Provider.
///
/// The access token will be removed from the ckms configuration file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LogoutAction;

impl LogoutAction {
    pub async fn process(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let mut conf = CliConf::load(conf_path)?;
        conf.kms_access_token = None;
        conf.save(conf_path)?;

        println!("\nThe access token was removed from the KMS configuration file: {conf_path:?}");

        Ok(())
    }
}
