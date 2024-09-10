use cosmian_kms_client::kmip::kmip_types::CryptographicUsageMask;
use serde::Deserialize;
use strum::EnumIter;

#[derive(clap::ValueEnum, Deserialize, Debug, Clone, EnumIter, PartialEq, Eq)]
pub enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    MACGenerate,
    MACVerify,
    DeriveKey,
    KeyAgreement,
    CertificateSign,
    CRLSign,
    Authenticate,
    Unrestricted,
}

impl From<KeyUsage> for String {
    fn from(key_usage: KeyUsage) -> Self {
        match key_usage {
            KeyUsage::Sign => "sign",
            KeyUsage::Verify => "verify",
            KeyUsage::Encrypt => "encrypt",
            KeyUsage::Decrypt => "decrypt",
            KeyUsage::WrapKey => "wrap-key",
            KeyUsage::UnwrapKey => "unwrap-key",
            KeyUsage::MACGenerate => "mac-generate",
            KeyUsage::MACVerify => "mac-verify",
            KeyUsage::DeriveKey => "derive-key",
            KeyUsage::KeyAgreement => "key-agreement",
            KeyUsage::CertificateSign => "certificate-sign",
            KeyUsage::CRLSign => "crl-sign",
            KeyUsage::Authenticate => "authenticate",
            KeyUsage::Unrestricted => "unrestricted",
        }
        .to_string()
    }
}

pub(crate) fn build_usage_mask_from_key_usage(
    key_usage_vec: &[KeyUsage],
) -> Option<CryptographicUsageMask> {
    let mut flags = 0;
    for key_usage in key_usage_vec {
        flags |= match key_usage {
            KeyUsage::Sign => CryptographicUsageMask::Sign,
            KeyUsage::Verify => CryptographicUsageMask::Verify,
            KeyUsage::Encrypt => CryptographicUsageMask::Encrypt,
            KeyUsage::Decrypt => CryptographicUsageMask::Decrypt,
            KeyUsage::WrapKey => CryptographicUsageMask::WrapKey,
            KeyUsage::UnwrapKey => CryptographicUsageMask::UnwrapKey,
            KeyUsage::MACGenerate => CryptographicUsageMask::MACGenerate,
            KeyUsage::MACVerify => CryptographicUsageMask::MACVerify,
            KeyUsage::DeriveKey => CryptographicUsageMask::DeriveKey,
            KeyUsage::KeyAgreement => CryptographicUsageMask::KeyAgreement,
            KeyUsage::CertificateSign => CryptographicUsageMask::CertificateSign,
            KeyUsage::CRLSign => CryptographicUsageMask::CRLSign,
            KeyUsage::Authenticate => CryptographicUsageMask::Authenticate,
            KeyUsage::Unrestricted => CryptographicUsageMask::Unrestricted,
        }
        .bits();
    }
    CryptographicUsageMask::from_bits(flags)
}
