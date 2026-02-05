use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, MaskGenerator, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicAlgorithm, DigitalSignatureAlgorithm, RecommendedCurve},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KmipPolicyConfig {
    /// Enable KMIP algorithm policy enforcement.
    ///
    /// When `false` (default), the server accepts any KMIP algorithm/parameter values supported
    /// by the implementation.
    ///
    /// When `true`, requests are checked against the allowlists below (or their defaults).
    /// Requests using a non-allowed algorithm/parameter are rejected.
    pub enforce: bool,

    /// Parameter-specific allowlists.
    ///
    /// These lists are config-only (not CLI flags) and are matched case-insensitively
    /// against KMIP enum Display names.
    ///
    /// If a list is `None`, no allowlist restriction is applied for that parameter.
    pub allowlists: KmipAllowlistsConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RsaKeySize {
    #[serde(rename = "2048")]
    Rsa2048,
    #[serde(rename = "3072")]
    Rsa3072,
    #[serde(rename = "4096")]
    Rsa4096,
}

impl RsaKeySize {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AesKeySize {
    #[serde(rename = "128")]
    Aes128,
    #[serde(rename = "192")]
    Aes192,
    #[serde(rename = "256")]
    Aes256,
    /// Some clients express AES-XTS keys as the total key size (e.g. 512 = 2×256).
    #[serde(rename = "512")]
    Aes512,
}

impl AesKeySize {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
            Self::Aes512 => 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::derivable_impls)]
pub struct KmipAllowlistsConfig {
    /// Allowed KMIP `CryptographicAlgorithm` values (e.g. "AES", "RSA").
    ///
    /// - `None`: do not restrict algorithms (any supported algorithm is accepted).
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub algorithms: Option<Vec<CryptographicAlgorithm>>,

    /// Allowed KMIP `HashingAlgorithm` values used by operations like Hash / MAC / MGF.
    ///
    /// - `None`: do not restrict hashes.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub hashes: Option<Vec<HashingAlgorithm>>,

    /// Allowed KMIP `DigitalSignatureAlgorithm` values (e.g. `ECDSAWithSHA256`).
    ///
    /// - `None`: do not restrict signature algorithms.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub signature_algorithms: Option<Vec<DigitalSignatureAlgorithm>>,

    /// Allowed KMIP `RecommendedCurve` values for EC keys (e.g. "P256", "CURVE25519").
    ///
    /// - `None`: do not restrict curves.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub curves: Option<Vec<RecommendedCurve>>,

    /// Allowed KMIP `BlockCipherMode` values (e.g. "GCM", "XTS").
    ///
    /// - `None`: do not restrict modes.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub block_cipher_modes: Option<Vec<BlockCipherMode>>,

    /// Allowed KMIP `PaddingMethod` values (e.g. "OAEP", "PSS", `PKCS1v15`).
    ///
    /// - `None`: do not restrict paddings.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub padding_methods: Option<Vec<PaddingMethod>>,

    /// Allowed RSA key sizes (in bits), matched against KMIP `CryptographicLength`.
    ///
    /// Example: `[3072, 4096]`.
    ///
    /// - `None`: do not restrict RSA key sizes.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub rsa_key_sizes: Option<Vec<RsaKeySize>>,

    /// Allowed AES key sizes (in bits), matched against KMIP `CryptographicLength`.
    ///
    /// Example: `[128, 192, 256]`.
    ///
    /// - `None`: do not restrict AES key sizes.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub aes_key_sizes: Option<Vec<AesKeySize>>,

    /// Allowed mask generator hash values (MGF1), used by RSA-OAEP / RSA-PSS.
    ///
    /// - `None`: do not restrict MGF hashes.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub mgf_hashes: Option<Vec<HashingAlgorithm>>,

    /// Allowed KMIP `MaskGenerator` values (e.g. "MGF1").
    ///
    /// This is used by RSA-OAEP / RSA-PSS.
    ///
    /// - `None`: do not restrict mask generators.
    /// - `[]` (empty): reject everything when `kmip.enforce = true`.
    pub mask_generators: Option<Vec<MaskGenerator>>,
}

#[allow(clippy::derivable_impls)]
impl Default for KmipAllowlistsConfig {
    fn default() -> Self {
        // Default is a conservative, recommended allowlist aligned with ANSSI/NIST/FIPS guidance.
        // Enforcement is gated by `kmip.enforce`.
        #[cfg(feature = "non-fips")]
        let algorithms = vec![
            // AES: the default symmetric primitive for encryption/wrapping (widest KMIP support).
            CryptographicAlgorithm::AES,
            // RSA/ECC: primary asymmetric primitives for key wrapping and signatures.
            CryptographicAlgorithm::RSA,
            CryptographicAlgorithm::ECDSA,
            // ECDH: standard KEM/KE agreement primitive for EC key agreement.
            CryptographicAlgorithm::ECDH,
            // EC: allows creation/import of generic EC keys used by ECDSA/ECDH.
            CryptographicAlgorithm::EC,
            // HMAC: message authentication with standard SHA-2 hashes.
            CryptographicAlgorithm::HMACSHA256,
            CryptographicAlgorithm::HMACSHA384,
            CryptographicAlgorithm::HMACSHA512,
            // Documented non-FIPS schemes (documentation/docs/algorithms.md).
            CryptographicAlgorithm::ChaCha20Poly1305,
            CryptographicAlgorithm::Ed25519,
            // ECIES fixed internal KDF/hash for standard curves uses SHAKE128.
            // When `kmip.enforce = true`, ECIES is denied unless SHAKE128 is allowlisted.
            CryptographicAlgorithm::SHAKE128,
            // Standard curves P-384/P-521 use SHAKE256 internally.
            // In strict mode (when the exact curve is not known), ECIES requires both SHAKE128 and SHAKE256.
            CryptographicAlgorithm::SHAKE256,
        ];

        #[cfg(not(feature = "non-fips"))]
        let algorithms = vec![
            // Conservative baseline: keep defaults to common profiles.
            CryptographicAlgorithm::AES,
            CryptographicAlgorithm::RSA,
            CryptographicAlgorithm::ECDSA,
            CryptographicAlgorithm::ECDH,
            CryptographicAlgorithm::EC,
            CryptographicAlgorithm::HMACSHA256,
            CryptographicAlgorithm::HMACSHA384,
            CryptographicAlgorithm::HMACSHA512,
        ];

        let signature_algorithms = vec![
            // X.509 / CMS interoperability: the most common RSA signature OIDs.
            DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
            // RSA-PSS: modern RSA signature padding.
            DigitalSignatureAlgorithm::RSASSAPSS,
            // ECDSA with SHA-2: common defaults for EC signatures.
            DigitalSignatureAlgorithm::ECDSAWithSHA256,
            DigitalSignatureAlgorithm::ECDSAWithSHA384,
            DigitalSignatureAlgorithm::ECDSAWithSHA512,
        ];

        Self {
            algorithms: Some(algorithms),
            hashes: Some(vec![
                // SHA-2: baseline hashing algorithms for interop and policy defaults.
                HashingAlgorithm::SHA256,
                HashingAlgorithm::SHA384,
                HashingAlgorithm::SHA512,
                // ANSSI also recommends SHA-3 family (FIPS202).
                HashingAlgorithm::SHA3256,
                HashingAlgorithm::SHA3384,
                HashingAlgorithm::SHA3512,
            ]),
            signature_algorithms: Some(signature_algorithms),
            curves: Some(vec![
                // NIST P-curves: broadly supported and standard for ECDSA/ECDH.
                RecommendedCurve::P256,
                RecommendedCurve::P384,
                RecommendedCurve::P521,
                // Curve25519: common for X25519 key agreement when policy permits.
                RecommendedCurve::CURVE25519,
                // Curve448: also recommended by ANSSI.
                RecommendedCurve::CURVE448,
            ]),
            block_cipher_modes: Some(vec![
                // Recommended AEAD / wrapping modes.
                // By default we intentionally exclude legacy streaming/chaining modes (CTR/OFB/CFB)
                // and non-AEAD block chaining modes (CBC/PCBC/CBCMAC/CBCMAC etc.).
                // GCM/CCM: standard AEAD modes (GCM is the most common).
                BlockCipherMode::GCM,
                BlockCipherMode::CCM,
                // XTS: disk/storage encryption mode; included for client interoperability.
                BlockCipherMode::XTS,
                // NIST key wrap (RFC 3394) and padding variant (RFC 5649): standard wrapping.
                BlockCipherMode::NISTKeyWrap,
                BlockCipherMode::AESKeyWrapPadding,
                // Documented scheme: AES GCM-SIV.
                BlockCipherMode::GCMSIV,
            ]),
            padding_methods: Some(vec![
                // OAEP/PSS: modern RSA encryption/signature paddings.
                PaddingMethod::OAEP,
                PaddingMethod::PSS,
                // PKCS#5 / PKCS#1 v1.5: retained for interoperability with legacy clients.
                PaddingMethod::PKCS5,
            ]),
            // ANSSI: RSA-2048 is not recommended anymore (R vs. legacy), prefer 3072+.
            rsa_key_sizes: Some(vec![RsaKeySize::Rsa3072, RsaKeySize::Rsa4096]),

            // ANSSI recommends AES with 128/192/256-bit keys.
            aes_key_sizes: Some(vec![
                AesKeySize::Aes128,
                AesKeySize::Aes192,
                AesKeySize::Aes256,
            ]),
            mgf_hashes: Some(vec![
                // MGF1 hash allowlist for RSA-OAEP/RSA-PSS; keep aligned with SHA-2 defaults.
                HashingAlgorithm::SHA256,
                HashingAlgorithm::SHA384,
                HashingAlgorithm::SHA512,
            ]),
            mask_generators: Some(vec![
                // RSA-OAEP/RSA-PSS: the standard KMIP mask generator.
                MaskGenerator::MFG1,
            ]),
        }
    }
}
