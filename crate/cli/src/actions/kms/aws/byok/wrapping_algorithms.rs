use clap::{Parser, ValueEnum};
use strum::{Display, EnumString};

/// The algorithm used with the RSA public key to protect key material during import.
///
/// For `RSA_AES` wrapping algorithms, you encrypt your key material with an AES key
/// that you generate, then encrypt your AES key with the RSA public key from AWS KMS.
/// For `RSA_AES` wrapping algorithms, you encrypt your key material directly with the
/// RSA public key from AWS KMS.
#[derive(Display, Parser, Debug, Clone, Copy, PartialEq, Eq, ValueEnum, EnumString)]
pub(crate) enum WrappingAlgorithm {
    /// Supported for all types of key material, except RSA key material (private key).
    /// Cannot be used with `RSA_2048` wrapping key spec to wrap `ECC_NIST_P521` key material.
    #[clap(name = "RSAES_OAEP_SHA_1")]
    RsaesOaepSha1,

    /// Supported for all types of key material, except RSA key material (private key).
    /// Cannot be used with `RSA_2048` wrapping key spec to wrap `ECC_NIST_P521` key material.
    #[clap(name = "RSAES_OAEP_SHA_256")]
    RsaesOaepSha256,

    /// Supported for wrapping RSA and ECC key material.
    /// Required for importing RSA private keys.
    #[clap(name = "RSA_AES_KEY_WRAP_SHA_1")]
    RsaAesKeyWrapSha1,

    /// Supported for wrapping RSA and ECC key material.
    /// Required for importing RSA private keys.
    #[clap(name = "RSA_AES_KEY_WRAP_SHA_256")]
    RsaAesKeyWrapSha256,

    /// Chinese SM2 public key encryption algorithm.
    #[clap(name = "SM2PKE")]
    Sm2Pke,
}
