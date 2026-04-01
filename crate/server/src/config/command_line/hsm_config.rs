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

    /// List of KMS usernames that are granted HSM admin privileges.
    /// HSM admins can create, destroy, and potentially export objects on the HSM.
    /// Use `"*"` as the only entry to grant all authenticated users admin access.
    /// Repeat the option or use a comma-separated list to specify multiple admins:
    ///   `--hsm-admin alice@example.com --hsm-admin bob@example.com`
    ///   or set `KMS_HSM_ADMIN=alice@example.com,bob@example.com`
    #[clap(
        verbatim_doc_comment,
        long,
        env = "KMS_HSM_ADMIN",
        value_delimiter = ',',
        num_args = 1..,
        default_value = HSM_ADMIN_DEFAULT
    )]
    pub hsm_admin: Vec<String>,

    /// HSM slot number. The slots used must be listed.
    /// Repeat this option to specify multiple slots
    /// while specifying a password for each slot (or an empty string for no password)
    /// e.g.
    /// ```sh
    ///   --hsm-slot 1 --hsm-password password1 \
    ///   --hsm-slot 2 --hsm-password password2
    /// ```
    #[clap(verbatim_doc_comment, long, env = "KMS_HSM_SLOT")]
    pub hsm_slot: Vec<usize>,

    /// Password for the user logging in to the HSM Slot specified with `--hsm_slot`
    /// Provide an empty string for no password
    /// see `--hsm_slot` for more information.
    /// Set `KMS_HSM_PASSWORD` to avoid the password appearing in `ps` output.
    #[clap(
        verbatim_doc_comment,
        long,
        env = "KMS_HSM_PASSWORD",
        requires = "hsm_slot"
    )]
    pub hsm_password: Vec<String>,
}
