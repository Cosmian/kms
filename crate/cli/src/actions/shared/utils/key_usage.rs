use cosmian_kms_client::kmip::kmip_types::CryptographicUsageMask;

#[derive(clap::ValueEnum, Debug, Clone)]
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

pub fn build_usage_mask_from_key_usage(
    key_usage_vec: &Option<Vec<KeyUsage>>,
) -> Option<CryptographicUsageMask> {
    match key_usage_vec {
        None => None,
        Some(key_usage_vec) => {
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
    }
}