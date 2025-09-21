use clap::Args;
use serde::{Deserialize, Serialize};

const HSM_ADMIN_DEFAULT: &str = "admin";

#[derive(Args, Clone, Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub struct HsmConfig {
    /// The HSM model.
    /// Trustway Proteccio and Utimaco General purpose HSMs are supported.
    #[clap(
        verbatim_doc_comment,
        long,
        value_parser(["proteccio", "utimaco", "softhsm2", "smartcardhsm"]),
        default_value = "proteccio"
    )]
    pub hsm_model: String,

    /// The username of the HSM admin.
    /// The HSM admin can create objects on the HSM, destroy them, and potentially export them.
    #[clap(long, env = "KMS_HSM_ADMIN", default_value = HSM_ADMIN_DEFAULT)]
    pub hsm_admin: String,

    /// HSM slot number. The slots used must be listed.
    /// Repeat this option to specify multiple slots
    /// while specifying a password for each slot (or an empty string for no password)
    /// e.g.
    /// ```sh
    ///   --hsm_slot 1 --hsm_password password1 \
    ///   --hsm_slot 2 --hsm_password password2
    ///```
    #[clap(verbatim_doc_comment, long)]
    pub hsm_slot: Vec<usize>,

    /// Password for the user logging in to the HSM Slot specified with `--hsm_slot`
    /// Provide an empty string for no password
    /// see `--hsm_slot` for more information
    #[clap(verbatim_doc_comment, long, requires = "hsm_slot")]
    pub hsm_password: Vec<String>,
}
