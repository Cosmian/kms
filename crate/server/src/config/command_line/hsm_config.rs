use std::fmt;

use clap::Args;
use serde::{Deserialize, Serialize};

const HSM_ADMIN_DEFAULT: &str = "admin";

/// Supported HSM models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmModel {
    Proteccio,
    Crypt2pay,
    Utimaco,
    Softhsm2,
    Smartcardhsm,
    Other,
}

impl HsmModel {
    pub const VARIANTS: &'static [Self] = &[
        Self::Proteccio,
        Self::Crypt2pay,
        Self::Utimaco,
        Self::Softhsm2,
        Self::Smartcardhsm,
        Self::Other,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proteccio => "proteccio",
            Self::Crypt2pay => "crypt2pay",
            Self::Utimaco => "utimaco",
            Self::Softhsm2 => "softhsm2",
            Self::Smartcardhsm => "smartcardhsm",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for HsmModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub struct HsmConfig {
    /// The HSM model.
    /// `Trustway Proteccio`, `Trustway Crypt2pay`, `Utimaco General Purpose HSM`,
    /// `Smartcard HSM`, and `SoftHSM2` are natively supported.
    /// Other HSMs are supported too; specify `other` and check the documentation
    #[clap(
        verbatim_doc_comment,
        long,
        value_parser(["proteccio", "crypt2pay", "utimaco", "softhsm2", "smartcardhsm", "other"]),
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
    ///   --hsm-slot 1 --hsm-password password1 \
    ///   --hsm-slot 2 --hsm-password password2
    /// ```
    #[clap(verbatim_doc_comment, long)]
    pub hsm_slot: Vec<usize>,

    /// Password for the user logging in to the HSM Slot specified with `--hsm_slot`
    /// Provide an empty string for no password
    /// see `--hsm_slot` for more information
    #[clap(verbatim_doc_comment, long, requires = "hsm_slot")]
    pub hsm_password: Vec<String>,
}
