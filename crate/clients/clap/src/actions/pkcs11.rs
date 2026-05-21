/// CLI commands for verifying the Cosmian PKCS#11 shared library.
///
/// These commands dynamically load the PKCS#11 `.so`/`.dylib`/`.dll` and exercise
/// the standard API sequence to confirm the library is functional and can
/// communicate with the KMS server.
use std::path::PathBuf;

use clap::Subcommand;

use crate::error::result::KmsCliResult;

/// Commands for verifying the Cosmian PKCS#11 provider library.
#[derive(Subcommand, Debug)]
pub enum Pkcs11Commands {
    /// Load the PKCS#11 shared library and exercise the standard API sequence.
    ///
    /// Verifies that the shared library opens, `ckms.toml` is parsed correctly,
    /// and the KMS server is reachable by walking through:
    /// `C_GetFunctionList` → `C_Initialize` → `C_GetSlotList` → `C_OpenSession` →
    /// `C_Login` (optional) → `C_FindObjects` → `C_CloseSession` → `C_Finalize`.
    Verify {
        /// Path to the PKCS#11 shared library (`libcosmian_pkcs11.so` / `.dylib` / `.dll`).
        #[arg(long, value_name = "PATH")]
        dll: PathBuf,

        /// Explicit path to `ckms.toml`. When set, the `CKMS_CONF` environment
        /// variable is written before the library is loaded so that the provider
        /// picks up this configuration file.
        #[arg(long, value_name = "PATH")]
        conf: Option<PathBuf>,

        /// Bearer token (OIDC/JWT) to pass to `C_Login`.
        /// Required when `ckms.toml` has `pkcs11_use_pin_as_access_token = true`.
        #[arg(long, value_name = "JWT")]
        token: Option<String>,
    },
}

impl Pkcs11Commands {
    /// Execute the PKCS#11 command.
    ///
    /// # Errors
    /// Returns an error if the verification sequence fails.
    pub fn process(&self) -> KmsCliResult<()> {
        match self {
            Self::Verify { dll, conf, token } => {
                super::pkcs11_verify::run_verify(dll, conf.as_deref(), token.as_deref())
            }
        }
    }
}
