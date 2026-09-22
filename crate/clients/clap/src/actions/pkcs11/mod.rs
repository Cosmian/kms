/// CLI commands for verifying the Cosmian PKCS#11 shared library.
///
/// These commands dynamically load the PKCS#11 `.so`/`.dylib`/`.dll` and exercise
/// the standard API sequence to confirm the library is functional and can
/// communicate with the KMS server.
use std::path::PathBuf;

pub(crate) mod bench;
pub(crate) mod capabilities;
pub(crate) mod verify;

pub use bench::Pkcs11BenchAction;
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

    /// Report on the full PKCS#11 v2/v3 surface: all 442 real `CKM_*` mechanisms
    /// and all 92 `C_*` functions, each marked ✅/❌/⏭️/⬛, every row printed
    /// individually.
    ///
    /// Two independent sections are printed: "PKCS#11 mechanism coverage" (the
    /// ~12 mechanisms `cosmian_pkcs11` advertises are deep-tested end to end
    /// across every provisioned curve; every other mechanism is probed via
    /// `C_GetMechanismInfo` alone) and "PKCS#11 API function coverage" (functions
    /// already exercised elsewhere are reported by reuse; the rest get one real
    /// shallow probe each). A mechanism/function that is genuinely unsupported
    /// (dynamically detected, e.g. `CKR_MECHANISM_INVALID`/
    /// `CKR_FUNCTION_NOT_SUPPORTED`) is marked ❌, same as a real attempted
    /// operation that failed; `⬛` is reserved for the handful of functions
    /// deliberately never invoked for safety (`C_InitToken`/`C_InitPIN`/
    /// `C_SetPIN`). RSA, EC (P-256/P-384/P-521, and in a `non-fips` build
    /// secp256k1), and (non-fips) Ed25519/Ed448 test key pairs are provisioned on
    /// the KMS via the REST API (`C_GenerateKeyPair` is not implemented by this
    /// provider) and destroyed again at the end unless `--keep-keys` is set. The
    /// AES key used for `CKM_AES_CBC`/`CKM_AES_CBC_PAD`/`CKM_AES_GCM` is generated
    /// live through `C_GenerateKey`.
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

    /// Benchmark the PKCS#11 provider's real Cryptoki C API: a concurrency-sweep
    /// load test, optional Criterion statistical micro-benchmarks, and an optional
    /// Ed25519 differential overhead ladder.
    Bench(Pkcs11BenchAction),
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
                verify::run_verify(dll, conf.as_deref(), token.as_deref())
            }
            Self::Capabilities {
                dll,
                conf,
                token,
                keep_keys,
            } => {
                capabilities::run_capabilities(
                    dll,
                    conf.as_deref(),
                    token.as_deref(),
                    kms_rest_client,
                    *keep_keys,
                )
                .await
            }
            Self::Bench(action) => Box::pin(action.process(kms_rest_client)).await,
        }
    }
}
