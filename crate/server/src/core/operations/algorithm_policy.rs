use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{
            BlockCipherMode, ErrorReason, HashingAlgorithm, MaskGenerator, PaddingMethod,
        },
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::{
                Create, CreateKeyPair, DeriveKey, Hash, MAC, MACVerify, Operation, Sign,
                SignatureVerify,
            },
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
                KeyFormatType, RecommendedCurve,
            },
        },
        ttlv::{TTLV, from_ttlv},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use crate::{config::ServerParams, error::KmsError, result::KResult};

#[derive(Default)]
struct KmipWhitelists {
    algorithms: Option<HashSet<CryptographicAlgorithm>>,
    hashes: Option<HashSet<HashingAlgorithm>>,
    signature_algorithms: Option<HashSet<DigitalSignatureAlgorithm>>,
    curves: Option<HashSet<RecommendedCurve>>,
    block_cipher_modes: Option<HashSet<BlockCipherMode>>,
    padding_methods: Option<HashSet<PaddingMethod>>,
    mgf_hashes: Option<HashSet<HashingAlgorithm>>,
    mask_generators: Option<HashSet<MaskGenerator>>,

    rsa_key_sizes: Option<HashSet<u32>>,
    aes_key_sizes: Option<HashSet<u32>>,
}

pub(crate) fn enforce_kmip_algorithm_policy_for_operation(
    params: &ServerParams,
    operation_tag: &str,
    ttlv: &TTLV,
) -> KResult<()> {
    let ttlv_tag_for_error = &ttlv.tag;
    // The root TTLV tag is the operation name (e.g. "Create").
    // Deserialize the *operation payload* (the struct), then wrap it into the `Operation` enum.
    let op = match operation_tag {
        "Create" => Operation::Create(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Create for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "CreateKeyPair" => Operation::CreateKeyPair(Box::new(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize CreateKeyPair for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?)),
        "Encrypt" => Operation::Encrypt(Box::new(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Encrypt for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?)),
        "Decrypt" => Operation::Decrypt(Box::new(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Decrypt for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?)),
        "Hash" => Operation::Hash(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Hash for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "MAC" => Operation::MAC(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize MAC for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "MACVerify" => Operation::MACVerify(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize MACVerify for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "Sign" => Operation::Sign(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Sign for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "SignatureVerify" => Operation::SignatureVerify(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize SignatureVerify for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "DeriveKey" => Operation::DeriveKey(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize DeriveKey for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "Import" => Operation::Import(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Import for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        "Register" => Operation::Register(from_ttlv(ttlv.clone()).map_err(|e| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "failed to deserialize Register for policy enforcement ({ttlv_tag_for_error}): {e}"
                ),
            )
        })?),
        // For other operations, request-time algorithm policy doesn't apply.
        _ => return Ok(()),
    };

    if !params.kmip_policy.enforce {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);

    #[allow(clippy::match_same_arms)]
    match op {
        Operation::Create(ref req) => validate_create(req, &wl),
        Operation::CreateKeyPair(ref req) => validate_create_key_pair(req.as_ref(), &wl),
        Operation::Encrypt(ref req) => {
            validate_cryptographic_parameters(&req.cryptographic_parameters, &wl)
        }
        Operation::Decrypt(ref req) => {
            validate_cryptographic_parameters(&req.cryptographic_parameters, &wl)
        }
        Operation::Hash(ref req) => validate_hash(req, &wl),
        Operation::MAC(ref req) => validate_mac(req, &wl),
        Operation::MACVerify(ref req) => validate_mac_verify(req, &wl),
        Operation::Sign(ref req) => validate_sign(req, &wl),
        Operation::SignatureVerify(ref req) => validate_signature_verify(req, &wl),
        Operation::DeriveKey(ref req) => validate_derive_key(req, &wl),
        Operation::Import(ref req) => validate_attributes(&req.attributes, &wl),
        Operation::Register(ref req) => validate_attributes(&req.attributes, &wl),

        // Rekey operations operate on existing objects; enforcement is done on retrieved keys and
        // on the Create/Import paths they invoke.
        Operation::ReKey(_) | Operation::ReKeyKeyPair(_) => Ok(()),
        // These operations do not carry enough standardized algorithm choice material for this
        // policy layer (they operate on an `Attribute`, not a full `Attributes` bag).
        Operation::SetAttribute(_)
        | Operation::ModifyAttribute(_)
        | Operation::AddAttribute(_)
        | Operation::DeleteAttribute(_) => Ok(()),
        _ => Ok(()),
    }
    .map_err(|e| {
        match e {
            KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
            other => {
                // Keep a stable KMIP error envelope.
                KmsError::Kmip21Error(
                    ErrorReason::Cryptographic_Failure,
                    format!(
                        "{operation_tag} denied by algorithm policy ({ttlv_tag_for_error}): {other}"
                    ),
                )
            }
        }
    })
}

impl KmipWhitelists {
    fn from_params(params: &crate::config::KmipPolicyParams) -> Self {
        Self {
            algorithms: params
                .allowlists
                .algorithms
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            hashes: params
                .allowlists
                .hashes
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            signature_algorithms: params
                .allowlists
                .signature_algorithms
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            curves: params
                .allowlists
                .curves
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            block_cipher_modes: params
                .allowlists
                .block_cipher_modes
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            padding_methods: params
                .allowlists
                .padding_methods
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            mgf_hashes: params
                .allowlists
                .mgf_hashes
                .as_deref()
                .map(|v| v.iter().copied().collect()),
            // KMIP encodes mask generator separately from the hashing algorithm (e.g., MGF1).
            mask_generators: params
                .allowlists
                .mask_generators
                .as_deref()
                .map(|v| v.iter().copied().collect()),

            rsa_key_sizes: params.allowlists.rsa_key_sizes.as_deref().map(|v| {
                v.iter()
                    .copied()
                    .map(crate::config::RsaKeySize::bits)
                    .collect::<HashSet<u32>>()
            }),
            aes_key_sizes: params.allowlists.aes_key_sizes.as_deref().map(|v| {
                v.iter()
                    .copied()
                    .map(crate::config::AesKeySize::bits)
                    .collect::<HashSet<u32>>()
            }),
        }
    }
}

pub(crate) fn enforce_kmip_algorithm_policy_for_retrieved_key(
    params: &ServerParams,
    operation_tag: &str,
    uid_for_error: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    let wl = if params.kmip_policy.enforce {
        KmipWhitelists::from_params(&params.kmip_policy)
    } else {
        KmipWhitelists::default()
    };
    let attrs = owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes());

    if let Some(alg) = attrs.cryptographic_algorithm {
        validate_algorithm(alg, wl.algorithms.as_ref()).map_err(|e| match e {
            KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
            other => KmsError::Kmip21Error(
                ErrorReason::Cryptographic_Failure,
                format!(
                    "{operation_tag} denied by algorithm policy (uid={uid_for_error}): {other}"
                ),
            ),
        })?;
    }

    if let (Some(alg), Some(bits)) = (attrs.cryptographic_algorithm, attrs.cryptographic_length) {
        validate_key_size_bits(alg, bits, &wl).map_err(|e| match e {
            KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
            other => KmsError::Kmip21Error(
                ErrorReason::Cryptographic_Failure,
                format!("{operation_tag} denied by key-size policy (uid={uid_for_error}): {other}"),
            ),
        })?;
    }

    // Enforce curves for EC keys when the curve is known.
    if let Ok(kb) = owm.object().key_block() {
        match kb.key_format_type {
            KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentECPrivateKey => {
                if let Some(domain) = attrs.cryptographic_domain_parameters.as_ref() {
                    if let Some(curve) = domain.recommended_curve {
                        validate_curve(curve, wl.curves.as_ref()).map_err(|e| match e {
                            KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
                            other => KmsError::Kmip21Error(
                                ErrorReason::Cryptographic_Failure,
                                format!(
                                    "{operation_tag} denied by curve policy (uid={uid_for_error}): {other}"
                                ),
                            ),
                        })?;
                    }
                }
            }
            _ => {}
        }
    } else if let Some(domain) = attrs.cryptographic_domain_parameters.as_ref() {
        if let Some(curve) = domain.recommended_curve {
            validate_curve(curve, wl.curves.as_ref()).map_err(|e| match e {
                KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
                other => KmsError::Kmip21Error(
                    ErrorReason::Cryptographic_Failure,
                    format!(
                        "{operation_tag} denied by curve policy (uid={uid_for_error}): {other}"
                    ),
                ),
            })?;
        }
    }

    Ok(())
}

fn allow<T: Eq + std::hash::Hash>(wl: Option<&HashSet<T>>, token: &T) -> bool {
    // Semantics:
    // - `None`: no restriction for this parameter (allow all)
    // - `Some(set)`: restriction enabled; only allow members (empty set => deny all)
    wl.is_none_or(|set| set.contains(token))
}

#[cfg(feature = "non-fips")]
pub(crate) fn enforce_ecies_fixed_suite_for_pkey_id(
    params: &ServerParams,
    operation_tag: &str,
    key_id: &str,
    pkey_id: openssl::pkey::Id,
) -> KResult<()> {
    // ECIES is gated by the general curve allowlist.
    // If curve restrictions are not configured, ECIES is considered disabled to avoid
    // accidental enablement (OpenSSL's PKey::id() does not expose the exact NIST curve).
    let allowed = match params.kmip_policy.allowlists.curves.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("{operation_tag}: ECIES is disabled by server policy (key={key_id})"),
            );
        }
    };

    let token = match pkey_id {
        openssl::pkey::Id::X25519 => "X25519",
        openssl::pkey::Id::EC => "P256/P384/P521",
        openssl::pkey::Id::ED25519 => "ED25519",
        other => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("{operation_tag}: ECIES not applicable to key type: {other:?}"),
            );
        }
    };

    // OpenSSL's PKey::id() does not expose the exact NIST curve. For fixed-suite enforcement,
    // we allow EC only when the KMIP policy already constrained curves at key creation/import.
    // For X25519, we can enforce directly.
    if pkey_id == openssl::pkey::Id::X25519 {
        if !allowed.contains(&RecommendedCurve::CURVE25519) {
            return deny(
                ErrorReason::Constraint_Violation,
                format!(
                    "{operation_tag}: ECIES curve not allowed by policy: {token} (key={key_id})"
                ),
            );
        }
    } else if pkey_id == openssl::pkey::Id::EC {
        // Require at least one of the NIST curves. Actual curve is enforced earlier via KMIP attributes.
        if !allowed.contains(&RecommendedCurve::P256)
            && !allowed.contains(&RecommendedCurve::P384)
            && !allowed.contains(&RecommendedCurve::P521)
        {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("{operation_tag}: ECIES EC curves not allowed by policy (key={key_id})"),
            );
        }
    } else if pkey_id == openssl::pkey::Id::ED25519 {
        #[cfg(feature = "non-fips")]
        {
            if !allowed.contains(&RecommendedCurve::CURVEED25519)
                && !allowed.contains(&RecommendedCurve::CURVE25519)
            {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "{operation_tag}: ECIES curve not allowed by policy: ED25519 (key={key_id})"
                    ),
                );
            }
        }

        #[cfg(not(feature = "non-fips"))]
        {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("{operation_tag}: ECIES not allowed for key type: ED25519 (key={key_id})"),
            );
        }
    } else {
        // ED25519 is not a key agreement curve; reject unless explicitly allowed and supported.
        return deny(
            ErrorReason::Constraint_Violation,
            format!("{operation_tag}: ECIES not allowed for key type: {token} (key={key_id})"),
        );
    }

    Ok(())
}

fn deny(reason: ErrorReason, msg: impl Into<String>) -> KResult<()> {
    Err(KmsError::Kmip21Error(reason, msg.into()))
}

fn validate_hash(req: &Hash, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&Some(req.cryptographic_parameters.clone()), wl)
}

fn validate_mac(req: &MAC, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&req.cryptographic_parameters, wl)
}

fn validate_mac_verify(req: &MACVerify, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&req.cryptographic_parameters, wl)
}

fn validate_sign(req: &Sign, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&req.cryptographic_parameters, wl)
}

fn validate_signature_verify(req: &SignatureVerify, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&req.cryptographic_parameters, wl)
}

fn validate_derive_key(req: &DeriveKey, wl: &KmipWhitelists) -> KResult<()> {
    validate_attributes(&req.attributes, wl)
}

fn validate_create(req: &Create, wl: &KmipWhitelists) -> KResult<()> {
    // Defensive: Create always carries an `Attributes` bag. If an algorithm is present,
    // it must be validated (including built-in denylists like DES).
    validate_attributes(&req.attributes, wl)
}

fn validate_create_key_pair(req: &CreateKeyPair, wl: &KmipWhitelists) -> KResult<()> {
    if let Some(attrs) = &req.common_attributes {
        validate_attributes(attrs, wl)?;
    }
    if let Some(attrs) = &req.private_key_attributes {
        validate_attributes(attrs, wl)?;
    }
    if let Some(attrs) = &req.public_key_attributes {
        validate_attributes(attrs, wl)?;
    }
    Ok(())
}

fn validate_attributes(attrs: &Attributes, wl: &KmipWhitelists) -> KResult<()> {
    // Validate algorithm choice
    if let Some(alg) = attrs.cryptographic_algorithm {
        validate_algorithm(alg, wl.algorithms.as_ref())?;
    }

    // Some KMIP requests provide the `CryptographicAlgorithm` only inside
    // `CryptographicParameters`.
    if attrs.cryptographic_algorithm.is_none() {
        if let Some(params) = &attrs.cryptographic_parameters {
            if let Some(alg) = params.cryptographic_algorithm {
                validate_algorithm(alg, wl.algorithms.as_ref())?;
            }
        }
    }

    // Validate sizes where present
    if let (Some(alg), Some(bits)) = (attrs.cryptographic_algorithm, attrs.cryptographic_length) {
        validate_key_size_bits(alg, bits, wl)?;
    }

    // Validate signature algorithm when present
    if let Some(sig_alg) = attrs.digital_signature_algorithm {
        validate_signature_algorithm(sig_alg, wl.signature_algorithms.as_ref())?;
    }

    // Validate curve restrictions
    if let Some(domain) = attrs.cryptographic_domain_parameters {
        if let Some(curve) = domain.recommended_curve {
            validate_curve(curve, wl.curves.as_ref())?;
        }
        if let (Some(q), Some(alg)) = (domain.qlength, attrs.cryptographic_algorithm) {
            validate_domain_qlength(alg, q)?;
        }
    }

    // Some requests also embed parameters
    if let Some(params) = &attrs.cryptographic_parameters {
        validate_cryptographic_parameters(&Some(params.clone()), wl)?;
    }

    Ok(())
}

fn validate_cryptographic_parameters(
    params: &Option<CryptographicParameters>,
    wl: &KmipWhitelists,
) -> KResult<()> {
    let Some(params) = params else {
        return Ok(());
    };

    if let Some(alg) = params.cryptographic_algorithm {
        validate_algorithm(alg, wl.algorithms.as_ref())?;
    }
    if let Some(hash) = params.hashing_algorithm {
        validate_hashing_algorithm(hash, wl.hashes.as_ref())?;
    }
    if let Some(sig) = params.digital_signature_algorithm {
        validate_signature_algorithm(sig, wl.signature_algorithms.as_ref())?;
    }

    if let Some(mode) = params.block_cipher_mode {
        validate_block_cipher_mode_typed(mode, wl.block_cipher_modes.as_ref())?;
    }

    // AES-XTS uses two keys and KMIP typically encodes the total key length (e.g., 512 bits).
    // This is exercised by non-FIPS integration tests and is permitted there.
    #[cfg(feature = "non-fips")]
    if params.cryptographic_algorithm == Some(CryptographicAlgorithm::AES)
        && params.block_cipher_mode == Some(BlockCipherMode::XTS)
    {
        // Skip the strict AES single-key length enforcement here; key sizes are validated
        // on object creation/import via attributes.
        return Ok(());
    }
    if let Some(padding) = params.padding_method {
        validate_padding_method_typed(padding, wl.padding_methods.as_ref())?;
    }
    if let Some(mgf) = params.mask_generator {
        validate_mask_generator_typed(mgf, wl.mask_generators.as_ref())?;
    }
    if let Some(mgf_hash) = params.mask_generator_hashing_algorithm {
        validate_hashing_algorithm(mgf_hash, wl.mgf_hashes.as_ref())?;
    }

    Ok(())
}

fn validate_block_cipher_mode_typed(
    mode: BlockCipherMode,
    whitelist: Option<&HashSet<BlockCipherMode>>,
) -> KResult<()> {
    if !allow(whitelist, &mode) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Mode not allowed by policy: {mode}"),
        );
    }
    Ok(())
}

fn validate_padding_method_typed(
    padding: PaddingMethod,
    whitelist: Option<&HashSet<PaddingMethod>>,
) -> KResult<()> {
    if !allow(whitelist, &padding) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Padding not allowed by policy: {padding}"),
        );
    }
    Ok(())
}

fn validate_mask_generator_typed(
    mgf: MaskGenerator,
    whitelist: Option<&HashSet<MaskGenerator>>,
) -> KResult<()> {
    if !allow(whitelist, &mgf) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Mask generator not allowed by policy: {mgf}"),
        );
    }
    Ok(())
}

fn validate_algorithm(
    alg: CryptographicAlgorithm,
    whitelist: Option<&HashSet<CryptographicAlgorithm>>,
) -> KResult<()> {
    // Default blacklist (deprecated/broken or not in requested scope)
    match alg {
        CryptographicAlgorithm::DES
        | CryptographicAlgorithm::THREE_DES
        | CryptographicAlgorithm::RC2
        | CryptographicAlgorithm::RC4
        | CryptographicAlgorithm::RC5
        | CryptographicAlgorithm::IDEA
        | CryptographicAlgorithm::CAST5
        | CryptographicAlgorithm::Blowfish
        | CryptographicAlgorithm::SKIPJACK
        | CryptographicAlgorithm::MARS
        | CryptographicAlgorithm::OneTimePad
        | CryptographicAlgorithm::HMACMD5
        | CryptographicAlgorithm::HMACSHA1
        | CryptographicAlgorithm::HMACSHA224
        | CryptographicAlgorithm::DSA
        | CryptographicAlgorithm::ECMQV => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated algorithm: {alg}"),
            );
        }
        _ => {}
    }

    // In-scope + still allowed (note: non-fips feature may add more algorithms)
    match alg {
        CryptographicAlgorithm::AES
        | CryptographicAlgorithm::RSA
        | CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::ECDH
        | CryptographicAlgorithm::EC
        | CryptographicAlgorithm::HMACSHA256
        | CryptographicAlgorithm::HMACSHA384
        | CryptographicAlgorithm::HMACSHA512
        | CryptographicAlgorithm::ChaCha20
        | CryptographicAlgorithm::Poly1305
        | CryptographicAlgorithm::ChaCha20Poly1305
        | CryptographicAlgorithm::SHA3224
        | CryptographicAlgorithm::SHA3256
        | CryptographicAlgorithm::SHA3384
        | CryptographicAlgorithm::SHA3512
        | CryptographicAlgorithm::HMACSHA3224
        | CryptographicAlgorithm::HMACSHA3256
        | CryptographicAlgorithm::HMACSHA3384
        | CryptographicAlgorithm::HMACSHA3512 => {}
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448
        | CryptographicAlgorithm::CoverCrypt
        | CryptographicAlgorithm::CoverCryptBulk => {}
        _ => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Algorithm out of policy scope: {alg}"),
            );
        }
    }

    if !allow(whitelist, &alg) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Algorithm not in recommended whitelist: {alg}"),
        );
    }

    Ok(())
}

fn validate_hashing_algorithm(
    hash: HashingAlgorithm,
    whitelist: Option<&HashSet<HashingAlgorithm>>,
) -> KResult<()> {
    match hash {
        HashingAlgorithm::MD2
        | HashingAlgorithm::MD4
        | HashingAlgorithm::MD5
        | HashingAlgorithm::SHA1
        | HashingAlgorithm::SHA224 => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated hash: {hash}"),
            );
        }
        _ => {}
    }
    if !allow(whitelist, &hash) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Hash not in recommended whitelist: {hash}"),
        );
    }
    Ok(())
}

fn validate_signature_algorithm(
    sig: DigitalSignatureAlgorithm,
    whitelist: Option<&HashSet<DigitalSignatureAlgorithm>>,
) -> KResult<()> {
    match sig {
        DigitalSignatureAlgorithm::MD2WithRSAEncryption
        | DigitalSignatureAlgorithm::MD5WithRSAEncryption
        | DigitalSignatureAlgorithm::SHA1WithRSAEncryption
        | DigitalSignatureAlgorithm::DSAWithSHA1
        | DigitalSignatureAlgorithm::ECDSAWithSHA1 => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated signature algorithm: {sig}"),
            );
        }
        _ => {}
    }

    if !allow(whitelist, &sig) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Signature algorithm not in recommended whitelist: {sig}"),
        );
    }

    Ok(())
}

fn validate_curve(
    curve: RecommendedCurve,
    whitelist: Option<&HashSet<RecommendedCurve>>,
) -> KResult<()> {
    // Default reject deprecated/weak curves.
    #[cfg(feature = "non-fips")]
    match curve {
        RecommendedCurve::ANSIX9P192V2
        | RecommendedCurve::ANSIX9P192V3
        | RecommendedCurve::ANSIX9P239V1
        | RecommendedCurve::ANSIX9P239V2
        | RecommendedCurve::ANSIX9P239V3 => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated curve: {curve}"),
            );
        }
        _ => {}
    }

    #[cfg(not(feature = "non-fips"))]
    match curve {
        RecommendedCurve::ANSIX9P192V2
        | RecommendedCurve::ANSIX9P192V3
        | RecommendedCurve::ANSIX9P239V1
        | RecommendedCurve::ANSIX9P239V2
        | RecommendedCurve::ANSIX9P239V3 => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated curve: {curve}"),
            );
        }
        _ => {}
    }

    // Allow P-256/P-384/P-521 and Curve25519 family.
    #[cfg(feature = "non-fips")]
    match curve {
        RecommendedCurve::P256
        | RecommendedCurve::P384
        | RecommendedCurve::P521
        | RecommendedCurve::SECP224K1
        | RecommendedCurve::SECP256K1
        | RecommendedCurve::CURVE25519
        | RecommendedCurve::CURVEED25519
        | RecommendedCurve::CURVEED448
        | RecommendedCurve::CURVE448 => {}
        _ => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Curve not in recommended set: {curve}"),
            );
        }
    }

    #[cfg(not(feature = "non-fips"))]
    match curve {
        RecommendedCurve::P256
        | RecommendedCurve::P384
        | RecommendedCurve::P521
        | RecommendedCurve::CURVE25519
        | RecommendedCurve::CURVEED25519
        | RecommendedCurve::CURVEED448
        | RecommendedCurve::CURVE448 => {}
        _ => {
            // Many named curves exist; keep it conservative.
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Curve not in recommended set: {curve}"),
            );
        }
    }

    if !allow(whitelist, &curve) {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Curve not in recommended whitelist: {curve}"),
        );
    }

    Ok(())
}

fn validate_key_size_bits(
    alg: CryptographicAlgorithm,
    bits: i32,
    wl: &KmipWhitelists,
) -> KResult<()> {
    if bits <= 0 {
        return deny(
            ErrorReason::Invalid_Field,
            "CryptographicLength must be > 0",
        );
    }

    let bits_u32 = u32::try_from(bits).map_err(|e| {
        KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            format!("CryptographicLength must be a non-negative integer: {e}"),
        )
    })?;
    #[allow(clippy::collapsible_if)]
    if alg == CryptographicAlgorithm::AES {
        if let Some(allowed) = wl.aes_key_sizes.as_ref() {
            if !allowed.contains(&bits_u32) {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!("AES key size not in allowed set: {bits}"),
                );
            }
        }
        // No allowlist configured: accept any positive length at this layer.
        // (Any further algorithm-specific constraints should live here, not in config parsing.)
    } else if alg == CryptographicAlgorithm::RSA {
        if let Some(allowed) = wl.rsa_key_sizes.as_ref() {
            if !allowed.contains(&bits_u32) {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!("RSA key size not in allowed set: {bits}"),
                );
            }
        }
        if bits_u32 < 2048 {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("RSA key size too small: {bits} (min 2048)"),
            );
        }
    }
    Ok(())
}

fn validate_domain_qlength(alg: CryptographicAlgorithm, q: i32) -> KResult<()> {
    if q <= 0 {
        return deny(
            ErrorReason::Invalid_Field,
            "CryptographicDomainParameters.Qlength must be > 0",
        );
    }
    // DSA/DH are deprecated/out-of-scope; still reject low q if provided.
    if (alg == CryptographicAlgorithm::DSA || alg == CryptographicAlgorithm::DH) && q < 224 {
        return deny(
            ErrorReason::Constraint_Violation,
            format!("Domain Q length too small: {q}"),
        );
    }
    Ok(())
}
