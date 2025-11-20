#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum CDigitalSignatureAlgorithm {
    RSASSAPSS,
    ECDSAWithSHA256,
    ECDSAWithSHA384,
    ECDSAWithSHA512,
}

impl CDigitalSignatureAlgorithm {
    #[must_use]
    pub fn to_cryptographic_parameters(self) -> CryptographicParameters {
        match self {
            Self::RSASSAPSS => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha1.into()),
                ..Default::default()
            },
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RSASSAPSS => "rsassa-pss",
        }
    }
}
