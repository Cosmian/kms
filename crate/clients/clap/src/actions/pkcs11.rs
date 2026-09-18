/// CLI commands for verifying the Cosmian PKCS#11 shared library.
///
/// These commands dynamically load the PKCS#11 `.so`/`.dylib`/`.dll` and exercise
/// the standard API sequence to confirm the library is functional and can
/// communicate with the KMS server.
use std::path::PathBuf;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::error::result::KmsCliResult;

/// Commands for verifying the Cosmian PKCS#11 provider library.
#[derive(Subcommand, Debug)]
pub enum Pkcs11Commands {
    /// Load the PKCS#11 shared library and exercise the standard v3.1 API sequence.
    ///
    /// Verifies that the shared library opens, `ckms.toml` is parsed correctly,
    /// and the KMS server is reachable by walking through:
    /// `C_GetInterfaceList`/`C_GetInterface` (v3.0 Interfaces API) →
    /// `C_GetFunctionList` → `C_Initialize` → `C_GetInfo` → `C_GetSlotList` →
    /// `C_GetMechanismList`/`C_GetMechanismInfo` → `C_OpenSession` →
    /// `C_Login` (optional) → `C_FindObjects` (including `CKO_PROFILE`
    /// self-declaration) → `C_CloseSession` → `C_Finalize`.
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

    /// Exhaustively exercise every PKCS#11 mechanism the `cosmian_pkcs11` DLL
    /// implements (key generation, encryption/decryption, signing/verification)
    /// and report a ✅/❌/⏭️ per mechanism.
    ///
    /// Unlike `verify`, which only walks the session/discovery API, this command
    /// actually runs the cryptographic operations end to end. RSA, EC (P-256, and
    /// in a `non-fips` build secp256k1), and (non-fips) Ed25519 test key pairs are
    /// provisioned on the KMS via the REST API (`C_GenerateKeyPair` is not
    /// implemented by this provider) and destroyed again at the end unless
    /// `--keep-keys` is set. The AES key used for `CKM_AES_CBC`/`CKM_AES_CBC_PAD`/
    /// `CKM_AES_GCM` is generated live through `C_GenerateKey`.
    Capabilities {
        /// Path to the PKCS#11 shared library (`libcosmian_pkcs11.so` / `.dylib` / `.dll`).
        #[arg(long, value_name = "PATH")]
        dll: PathBuf,

        /// Explicit path to `ckms.toml`. When set, the `CKMS_CONF` environment
        /// variable is written before the library is loaded so that the provider
        /// picks up this configuration file.
        #[arg(long, value_name = "PATH")]
        conf: Option<PathBuf>,

        /// ****** (OIDC/JWT) to pass to `C_Login`.
        /// Required when `ckms.toml` has `pkcs11_use_pin_as_access_token = true`.
        #[arg(long, value_name = "JWT")]
        token: Option<String>,

        /// Do not destroy the KMS test keys provisioned for this run.
        #[arg(long, default_value = "false")]
        keep_keys: bool,
    },
}

impl Pkcs11Commands {
    /// Execute the PKCS#11 command.
    ///
    /// # Errors
    /// Returns an error if the verification sequence fails, or if the PKCS#11
    /// shared library or KMS session cannot be initialized for `capabilities`.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Verify { dll, conf, token } => {
                super::pkcs11_verify::run_verify(dll, conf.as_deref(), token.as_deref())
            }
            Self::Capabilities {
                dll,
                conf,
                token,
                keep_keys,
            } => {
                super::pkcs11_capabilities::run_capabilities(
                    dll,
                    conf.as_deref(),
                    token.as_deref(),
                    kms_rest_client,
                    *keep_keys,
                )
                .await
            }
        }
    }
}
