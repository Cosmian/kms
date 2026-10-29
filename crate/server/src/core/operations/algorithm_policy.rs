use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{
            BlockCipherMode, ErrorReason, HashingAlgorithm, MaskGenerator, PaddingMethod,
        },
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::KeyMaterial,
            kmip_objects::ObjectType,
            kmip_operations::{
                Create, CreateKeyPair, DeriveKey, Export, Hash, MAC, MACVerify, Operation, Sign,
                SignatureVerify,
            },
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
                KeyFormatType, OperationEnumeration, RecommendedCurve,
            },
        },
        ttlv::{TTLV, TtlvDeserializer},
    },
    cosmian_kms_crypto::openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, oid::nid_of,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use openssl::{
    asn1::Asn1Object,
    nid::Nid,
    pkey::{HasPublic, Id, PKeyRef},
    x509::X509ReqRef,
};
use serde::Deserialize;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509CertificationRequest};

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
    operation: OperationEnumeration,
    ttlv: &TTLV,
) -> KResult<()> {
    use OperationEnumeration as Op;

    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let ttlv_tag_for_error = &ttlv.tag;

    macro_rules! deserialize_op {
        ($ty:ty, $name:expr) => {{
            let mut deserializer = TtlvDeserializer::from_ttlv(ttlv);
            <$ty>::deserialize(&mut deserializer).map_err(|e| {
                KmsError::Kmip21Error(
                    ErrorReason::Invalid_Message,
                    format!(
                        "failed to deserialize {} for policy enforcement ({}): {}",
                        $name, ttlv_tag_for_error, e
                    ),
                )
            })
        }};
    }
    // Deserialize the *operation payload* (the struct), then wrap it into the `Operation` enum.
    let op = match operation {
        Op::Create => Operation::Create(deserialize_op!(Create, "Create")?),
        Op::CreateKeyPair => Operation::CreateKeyPair(Box::new(deserialize_op!(CreateKeyPair, "CreateKeyPair")?)),
        Op::Encrypt => Operation::Encrypt(Box::new(deserialize_op!(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Encrypt, "Encrypt")?)),
        Op::Decrypt => Operation::Decrypt(Box::new(deserialize_op!(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Decrypt, "Decrypt")?)),
        Op::Hash => Operation::Hash(deserialize_op!(Hash, "Hash")?),
        Op::MAC => Operation::MAC(deserialize_op!(MAC, "MAC")?),
        Op::MACVerify => Operation::MACVerify(deserialize_op!(MACVerify, "MACVerify")?),
        Op::Sign => Operation::Sign(deserialize_op!(Sign, "Sign")?),
        Op::SignatureVerify => Operation::SignatureVerify(deserialize_op!(SignatureVerify, "SignatureVerify")?),
        Op::DeriveKey => Operation::DeriveKey(deserialize_op!(DeriveKey, "DeriveKey")?),
        Op::Import => Operation::Import(Box::new(deserialize_op!(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Import, "Import")?)),
        Op::Register => Operation::Register(Box::new(deserialize_op!(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Register, "Register")?)),
        Op::Export => Operation::Export(deserialize_op!(Export, "Export")?),
        // For other operations, request-time algorithm policy doesn't apply.
        _ => return Ok(()),
    };

    enforce_kmip_algorithm_policy_for_request(params, &op)
}

/// Request-time algorithm policy for an already-deserialized request (batched
/// `RequestMessage` items and the TTLV path after deserialization).
pub(crate) fn enforce_kmip_algorithm_policy_for_request(
    params: &ServerParams,
    op: &Operation,
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);

    #[allow(clippy::match_same_arms)]
    // arms bind distinct request types; merging with `|` would lose the typed `req` binding
    match op {
        Operation::Create(req) => validate_create(req, &wl),
        Operation::CreateKeyPair(req) => validate_create_key_pair(req.as_ref(), &wl),
        Operation::Encrypt(req) => {
            validate_cryptographic_parameters(&req.cryptographic_parameters, &wl)
        }
        Operation::Decrypt(req) => {
            validate_cryptographic_parameters(&req.cryptographic_parameters, &wl)
        }
        Operation::Hash(req) => validate_hash(req, &wl),
        Operation::MAC(req) => validate_mac(req, &wl),
        Operation::MACVerify(req) => validate_mac_verify(req, &wl),
        Operation::Sign(req) => validate_sign(req, &wl),
        Operation::SignatureVerify(req) => validate_signature_verify(req, &wl),
        Operation::DeriveKey(req) => validate_derive_key(req, &wl),
        Operation::Import(req) => validate_attributes(&req.attributes, &wl),
        Operation::Register(req) => validate_attributes(&req.attributes, &wl),
        Operation::Export(req) => validate_export(req, &wl),

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
        wrap_policy_error(
            e,
            &op.operation_enum().to_string(),
            "denied by algorithm policy",
        )
    })
}

/// Keep the KMIP error envelope: KMIP/invalid-request errors pass through, others become
/// `Cryptographic_Failure`. No object UIDs in the message (EST returns it to the device).
fn wrap_policy_error(e: KmsError, operation_tag: &str, what: &str) -> KmsError {
    match e {
        KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
        other => KmsError::Kmip21Error(
            ErrorReason::Cryptographic_Failure,
            format!("{operation_tag} {what}: {other}"),
        ),
    }
}

/// ML-DSA parameter sets (FIPS 204), by `OpenSSL` short name (`rust-openssl` has no constants).
const ML_DSA_ALGORITHMS: [(&str, CryptographicAlgorithm); 3] = [
    ("id-ml-dsa-44", CryptographicAlgorithm::MLDSA_44),
    ("id-ml-dsa-65", CryptographicAlgorithm::MLDSA_65),
    ("id-ml-dsa-87", CryptographicAlgorithm::MLDSA_87),
];

/// RSA PKCS#1 v1.5 with SHA-3 signatures (RFC 9688), by `OpenSSL` short name.
const SHA3_RSA_SIGNATURES: [(&str, DigitalSignatureAlgorithm); 3] = [
    (
        "id-rsassa-pkcs1-v1_5-with-sha3-256",
        DigitalSignatureAlgorithm::SHA3256WithRSAEncryption,
    ),
    (
        "id-rsassa-pkcs1-v1_5-with-sha3-384",
        DigitalSignatureAlgorithm::SHA3384WithRSAEncryption,
    ),
    (
        "id-rsassa-pkcs1-v1_5-with-sha3-512",
        DigitalSignatureAlgorithm::SHA3512WithRSAEncryption,
    ),
];

/// The NID of an `OpenSSL` object name, or [`Nid::UNDEF`] when this build does not know it.
fn nid_by_name(name: &str) -> Nid {
    Asn1Object::from_str(name).map_or(Nid::UNDEF, |obj| obj.nid())
}

/// ML-DSA algorithm of a key OpenSSL reports under no known `Id`, from its SPKI algorithm.
fn algorithm_from_spki_oid<T: HasPublic>(key: &PKeyRef<T>) -> Option<CryptographicAlgorithm> {
    let der = key.public_key_to_der().ok()?;
    let (_, spki) = SubjectPublicKeyInfo::from_der(&der).ok()?;
    let nid = nid_of(&spki.algorithm.algorithm.to_id_string());
    ML_DSA_ALGORITHMS
        .iter()
        .find(|(name, _)| nid != Nid::UNDEF && nid_by_name(name) == nid)
        .map(|(_, alg)| *alg)
}

/// Certify: the certified public key must satisfy the active algorithm policy.
/// `attributes_hint` (the KMIP attributes of the key, when it is a KMS object) names the
/// algorithm of key types OpenSSL does not identify (e.g. ML-DSA).
pub(crate) fn enforce_kmip_algorithm_policy_for_public_key<T: HasPublic>(
    params: &ServerParams,
    operation_tag: &str,
    public_key: &PKeyRef<T>,
    attributes_hint: Option<&Attributes>,
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);
    (|| -> KResult<()> {
        let (alg, curve) = match public_key.id() {
            Id::RSA => {
                validate_algorithm(CryptographicAlgorithm::RSA, wl.algorithms.as_ref())?;
                let bits = i32::try_from(public_key.bits()).map_err(|e| {
                    KmsError::InvalidRequest(format!("{operation_tag}: invalid RSA key size: {e}"))
                })?;
                return validate_key_size_bits(CryptographicAlgorithm::RSA, bits, &wl);
            }
            Id::EC => {
                let ec_key = public_key.ec_key()?;
                let nid = ec_key.group().curve_name();
                let curve = match nid {
                    #[cfg(feature = "non-fips")]
                    Some(Nid::X9_62_PRIME192V1) => Some(RecommendedCurve::P192),
                    Some(Nid::SECP224R1) => Some(RecommendedCurve::P224),
                    Some(Nid::X9_62_PRIME256V1) => Some(RecommendedCurve::P256),
                    Some(Nid::SECP384R1) => Some(RecommendedCurve::P384),
                    Some(Nid::SECP521R1) => Some(RecommendedCurve::P521),
                    #[cfg(feature = "non-fips")]
                    Some(Nid::SECP256K1) => Some(RecommendedCurve::SECP256K1),
                    #[cfg(feature = "non-fips")]
                    Some(Nid::SECP224K1) => Some(RecommendedCurve::SECP224K1),
                    #[cfg(feature = "non-fips")]
                    Some(Nid::SECP192K1) => Some(RecommendedCurve::SECP192K1),
                    _ => None,
                };
                let Some(curve) = curve else {
                    let name = nid
                        .and_then(|n| n.short_name().ok())
                        .unwrap_or("explicit parameters");
                    return deny(
                        ErrorReason::Constraint_Violation,
                        format!(
                            "{operation_tag}: EC curve {name} is not covered by the algorithm policy"
                        ),
                    );
                };
                (CryptographicAlgorithm::EC, curve)
            }
            Id::ED25519 => (
                CryptographicAlgorithm::Ed25519,
                RecommendedCurve::CURVEED25519,
            ),
            Id::ED448 => (CryptographicAlgorithm::Ed448, RecommendedCurve::CURVEED448),
            Id::X25519 => (CryptographicAlgorithm::ECDH, RecommendedCurve::CURVE25519),
            Id::X448 => (CryptographicAlgorithm::ECDH, RecommendedCurve::CURVE448),
            _ => {
                let Some(alg) = algorithm_from_spki_oid(public_key)
                    .or_else(|| attributes_hint.and_then(|a| a.cryptographic_algorithm))
                else {
                    return deny(
                        ErrorReason::Constraint_Violation,
                        format!(
                            "{operation_tag}: the public key type is not covered by the algorithm policy"
                        ),
                    );
                };
                validate_algorithm(alg, wl.algorithms.as_ref())?;
                if let Some(bits) = attributes_hint.and_then(|a| a.cryptographic_length) {
                    validate_key_size_bits(alg, bits, &wl)?;
                }
                return Ok(());
            }
        };
        validate_algorithm(alg, wl.algorithms.as_ref())?;
        validate_curve(curve, wl.curves.as_ref())
    })()
    .map_err(|e| wrap_policy_error(e, operation_tag, "denied by algorithm policy"))
}

/// Certify from a PKCS#10 request: its public key and, for RSA and EC keys (whose signature
/// names a hash), its signature algorithm must satisfy the active algorithm policy.
pub(crate) fn enforce_kmip_algorithm_policy_for_csr(
    params: &ServerParams,
    csr: &X509ReqRef,
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let key = csr.public_key()?;
    enforce_kmip_algorithm_policy_for_public_key(params, "Certify", &key, None)?;
    if !matches!(key.id(), Id::RSA | Id::EC) {
        return Ok(());
    }
    let der = csr.to_der()?;
    let (_, req) = X509CertificationRequest::from_der(&der)
        .map_err(|e| KmsError::InvalidRequest(format!("CSR cannot be parsed: {e}")))?;
    let oid = req.signature_algorithm.algorithm.to_id_string();
    let nid = nid_of(&oid);
    let sig = match nid {
        Nid::MD5WITHRSAENCRYPTION => DigitalSignatureAlgorithm::MD5WithRSAEncryption,
        Nid::SHA1WITHRSAENCRYPTION => DigitalSignatureAlgorithm::SHA1WithRSAEncryption,
        Nid::SHA224WITHRSAENCRYPTION => DigitalSignatureAlgorithm::SHA224WithRSAEncryption,
        Nid::SHA256WITHRSAENCRYPTION => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
        Nid::SHA384WITHRSAENCRYPTION => DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
        Nid::SHA512WITHRSAENCRYPTION => DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
        Nid::RSASSAPSS => DigitalSignatureAlgorithm::RSASSAPSS,
        Nid::ECDSA_WITH_SHA1 => DigitalSignatureAlgorithm::ECDSAWithSHA1,
        Nid::ECDSA_WITH_SHA224 => DigitalSignatureAlgorithm::ECDSAWithSHA224,
        Nid::ECDSA_WITH_SHA256 => DigitalSignatureAlgorithm::ECDSAWithSHA256,
        Nid::ECDSA_WITH_SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
        Nid::ECDSA_WITH_SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
        // `rust-openssl` has no constants for the RSA-with-SHA-3 NIDs: resolve them by name.
        _ => SHA3_RSA_SIGNATURES
            .iter()
            .find(|(name, _)| nid != Nid::UNDEF && nid_by_name(name) == nid)
            .map(|(_, sig)| *sig)
            .ok_or_else(|| {
                KmsError::Kmip21Error(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "Certify: CSR signature algorithm {oid} is not covered by the algorithm \
                         policy"
                    ),
                )
            })?,
    };
    let wl = KmipWhitelists::from_params(&params.kmip_policy);
    validate_signature_algorithm(sig, wl.signature_algorithms.as_ref())
        .map_err(|e| wrap_policy_error(e, "Certify", "denied by algorithm policy"))
}

fn validate_export(req: &Export, wl: &KmipWhitelists) -> KResult<()> {
    // Export may declare a Key Wrapping Specification with embedded CryptographicParameters.
    // Those parameters represent algorithm choices made by the caller and must be validated
    // against the configured allowlists.
    if let Some(spec) = &req.key_wrapping_specification {
        if let Some(eki) = &spec.encryption_key_information {
            if let Some(cp) = &eki.cryptographic_parameters {
                validate_cryptographic_parameters(&Some(cp.clone()), wl)?;
            }
        }
    }
    Ok(())
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

/// Policy check for a stored key before it is used.
///
/// Attributes are the fast path. When one is missing, the `KeyBlock` algorithm and length
/// (set from the key material, not editable through attribute operations) stand in for it,
/// and the curve is read from the key itself. A curve-based key whose curve cannot be
/// determined is refused when a curve allowlist is active (fail closed).
pub(crate) fn enforce_kmip_algorithm_policy_for_retrieved_key(
    params: &ServerParams,
    operation_tag: &str,
    uid_for_error: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);
    let object = owm.object();
    let attrs = object.attributes().unwrap_or_else(|_| owm.attributes());
    let key_block = object.key_block().ok();
    // A `ConfigurableKEM` key is judged by the components serialized in its key bytes, where it
    // is used (`enforce_kmip_algorithm_policy_for_kem_components`): its importer-controlled
    // attributes must neither deny nor allow it.
    if key_block.is_some_and(|kb| {
        matches!(
            kb.key_format_type,
            KeyFormatType::ConfigurableKEMPublicKey | KeyFormatType::ConfigurableKEMSecretKey
        )
    }) {
        return Ok(());
    }
    let alg = attrs
        .cryptographic_algorithm
        .or_else(|| key_block.and_then(|kb| kb.cryptographic_algorithm));
    (|| -> KResult<()> {
        if let Some(alg) = alg {
            validate_algorithm(alg, wl.algorithms.as_ref())?;
            if let Some(bits) = attrs
                .cryptographic_length
                .or_else(|| key_block.and_then(|kb| kb.cryptographic_length))
            {
                validate_key_size_bits(alg, bits, &wl)?;
            }
        }
        // Stored parameters fill what a request omits (e.g. Encrypt's block cipher mode) and
        // clients may edit them, so they are checked when the key is used.
        validate_cryptographic_parameters(&attrs.cryptographic_parameters, &wl)?;
        validate_retrieved_key_curve(params, operation_tag, owm, attrs, alg, &wl)
    })()
    .map_err(|e| {
        wrap_policy_error(
            e,
            operation_tag,
            &format!("denied by algorithm policy (uid={uid_for_error})"),
        )
    })
}

/// Curve check of [`enforce_kmip_algorithm_policy_for_retrieved_key`].
fn validate_retrieved_key_curve(
    params: &ServerParams,
    operation_tag: &str,
    owm: &ObjectWithMetadata,
    attrs: &Attributes,
    alg: Option<CryptographicAlgorithm>,
    wl: &KmipWhitelists,
) -> KResult<()> {
    let object = owm.object();
    if let Ok(
        KeyMaterial::TransparentECPrivateKey {
            recommended_curve, ..
        }
        | KeyMaterial::TransparentECPublicKey {
            recommended_curve, ..
        },
    ) = object.key_block().and_then(|kb| kb.key_material())
    {
        return validate_curve(*recommended_curve, wl.curves.as_ref());
    }
    if let Some(curve) = attrs
        .cryptographic_domain_parameters
        .and_then(|d| d.recommended_curve)
    {
        return validate_curve(curve, wl.curves.as_ref());
    }
    let is_asymmetric_key = matches!(
        object.object_type(),
        ObjectType::PrivateKey | ObjectType::PublicKey
    );
    let needs_key_material = (alg.is_none() && wl.algorithms.is_some())
        || (alg.is_some_and(is_curve_algorithm) && wl.curves.is_some());
    if !is_asymmetric_key || !needs_key_material {
        return Ok(());
    }
    if object.is_wrapped() {
        return deny(
            ErrorReason::Constraint_Violation,
            "the algorithm or curve of this wrapped key is not recorded in its attributes",
        );
    }
    if object.object_type() == ObjectType::PrivateKey {
        let key = kmip_private_key_to_openssl(object)?;
        enforce_kmip_algorithm_policy_for_public_key(params, operation_tag, &key, Some(attrs))
    } else {
        let key = kmip_public_key_to_openssl(object)?;
        enforce_kmip_algorithm_policy_for_public_key(params, operation_tag, &key, Some(attrs))
    }
}

/// Algorithms whose keys are defined on a named curve.
const fn is_curve_algorithm(alg: CryptographicAlgorithm) -> bool {
    matches!(
        alg,
        CryptographicAlgorithm::EC
            | CryptographicAlgorithm::ECDSA
            | CryptographicAlgorithm::ECDH
            | CryptographicAlgorithm::ECMQV
            | CryptographicAlgorithm::Ed25519
            | CryptographicAlgorithm::Ed448
    )
}

/// Enforce the policy on the components of a `ConfigurableKEM` key as read from the key
/// bytes (see `kem_key_components`), not from its KMIP attributes, which an importer
/// controls: a key relabelled or stripped of its component attributes cannot bypass it.
#[cfg(feature = "non-fips")]
pub(crate) fn enforce_kmip_algorithm_policy_for_kem_components(
    params: &ServerParams,
    operation_tag: &str,
    uid_for_error: &str,
    (curve, algorithm): (Option<RecommendedCurve>, Option<CryptographicAlgorithm>),
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);
    [Some(CryptographicAlgorithm::ConfigurableKEM), algorithm]
        .into_iter()
        .flatten()
        .try_for_each(|alg| validate_algorithm(alg, wl.algorithms.as_ref()))
        .and_then(|()| curve.map_or(Ok(()), |c| validate_curve(c, wl.curves.as_ref())))
        .map_err(|e| match e {
            KmsError::Kmip21Error(_, _) | KmsError::InvalidRequest(_) => e,
            other => KmsError::Kmip21Error(
                ErrorReason::Cryptographic_Failure,
                format!(
                    "{operation_tag} denied by algorithm policy (uid={uid_for_error}): {other}"
                ),
            ),
        })
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
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);
    // ECIES uses a fixed internal suite. Curve allowlists apply as follows:
    // - `None`: no curve restriction (default-on)
    // - `Some(empty)`: deny all curves
    // - `Some(non-empty)`: restrict to listed curves
    let allowed = params.kmip_policy.allowlists.curves.as_deref();
    if let Some(set) = allowed {
        if set.is_empty() {
            return deny(
                ErrorReason::Constraint_Violation,
                format!(
                    "{operation_tag}: ECIES is disabled by server policy (empty curve allowlist) (key={key_id})"
                ),
            );
        }
    }

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
        if let Some(set) = allowed {
            if !set.contains(&RecommendedCurve::CURVE25519) {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "{operation_tag}: ECIES curve not allowed by policy: {token} (key={key_id})"
                    ),
                );
            }
        }
    } else if pkey_id == openssl::pkey::Id::EC {
        // Require at least one of the NIST curves. Actual curve is enforced earlier via KMIP attributes.
        if let Some(set) = allowed {
            if !set.contains(&RecommendedCurve::P256)
                && !set.contains(&RecommendedCurve::P384)
                && !set.contains(&RecommendedCurve::P521)
            {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "{operation_tag}: ECIES EC curves not allowed by policy (key={key_id})"
                    ),
                );
            }
        }
    } else if pkey_id == openssl::pkey::Id::ED25519 {
        #[cfg(feature = "non-fips")]
        {
            if let Some(set) = allowed {
                if !set.contains(&RecommendedCurve::CURVEED25519)
                    && !set.contains(&RecommendedCurve::CURVE25519)
                {
                    return deny(
                        ErrorReason::Constraint_Violation,
                        format!(
                            "{operation_tag}: ECIES curve not allowed by policy: ED25519 (key={key_id})"
                        ),
                    );
                }
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

    // ECIES uses a fixed internal suite (not expressed in KMIP request parameters).
    // For *standard curves* (P-*), the KDF/hash is SHAKE128/256.
    // Strict fallback policy: when the exact curve is not known at this point (OpenSSL's
    // `PKey::id()` is only `EC`), require *both* SHAKE128 and SHAKE256 to be allowlisted.
    if pkey_id == openssl::pkey::Id::EC {
        for shake_token in [
            CryptographicAlgorithm::SHAKE128,
            CryptographicAlgorithm::SHAKE256,
        ] {
            if !allow(wl.algorithms.as_ref(), &shake_token) {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "{operation_tag}: ECIES internal algorithm not allowed by policy: {shake_token:?} (key={key_id})"
                    ),
                );
            }
        }
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
pub(crate) fn enforce_ecies_fixed_suite_for_attributes(
    params: &ServerParams,
    operation_tag: &str,
    key_id: &str,
    attrs: &Attributes,
) -> KResult<()> {
    if params.kmip_policy.policy_id.is_none() {
        return Ok(());
    }
    let wl = KmipWhitelists::from_params(&params.kmip_policy);

    // Curve allowlists apply as follows:
    // - `None`: no curve restriction (default-on)
    // - `Some(empty)`: deny all curves
    // - `Some(non-empty)`: restrict to listed curves
    let allowed_curves = params.kmip_policy.allowlists.curves.as_deref();
    if let Some(set) = allowed_curves {
        if set.is_empty() {
            return deny(
                ErrorReason::Constraint_Violation,
                format!(
                    "{operation_tag}: ECIES is disabled by server policy (empty curve allowlist) (key={key_id})"
                ),
            );
        }
    }

    let recommended_curve = attrs
        .cryptographic_domain_parameters
        .as_ref()
        .and_then(|dp| dp.recommended_curve);

    // If we know the curve, enforce the precise SHAKE requirement.
    if let Some(curve) = recommended_curve {
        if let Some(set) = allowed_curves {
            if !set.contains(&curve) {
                return deny(
                    ErrorReason::Constraint_Violation,
                    format!(
                        "{operation_tag}: ECIES curve not allowed by policy: {curve:?} (key={key_id})"
                    ),
                );
            }
        }

        let required_shake = match curve {
            RecommendedCurve::P384 | RecommendedCurve::P521 => CryptographicAlgorithm::SHAKE256,
            // Default for standard curves (including P-256) is SHAKE128.
            _ => CryptographicAlgorithm::SHAKE128,
        };

        if !allow(wl.algorithms.as_ref(), &required_shake) {
            return deny(
                ErrorReason::Constraint_Violation,
                format!(
                    "{operation_tag}: ECIES internal algorithm not allowed by policy: {required_shake:?} (key={key_id})"
                ),
            );
        }
        return Ok(());
    }

    // If the curve is unknown from attributes, fall back to strict ID-based enforcement.
    enforce_ecies_fixed_suite_for_pkey_id(params, operation_tag, key_id, openssl::pkey::Id::EC)
}

fn deny(reason: ErrorReason, msg: impl Into<String>) -> KResult<()> {
    Err(KmsError::Kmip21Error(reason, msg.into()))
}

fn validate_hash(req: &Hash, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters(&Some(req.cryptographic_parameters.clone()), wl)
}

fn validate_mac(req: &MAC, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters_for_mac(&req.cryptographic_parameters, wl)
}

fn validate_mac_verify(req: &MACVerify, wl: &KmipWhitelists) -> KResult<()> {
    validate_cryptographic_parameters_for_mac(&req.cryptographic_parameters, wl)
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

    // Some KMIP requests provide a `CryptographicAlgorithm` inside the
    // `CryptographicParameters`.
    if let Some(params) = &attrs.cryptographic_parameters {
        if let Some(alg) = params.cryptographic_algorithm {
            validate_algorithm(alg, wl.algorithms.as_ref())?;
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
        | CryptographicAlgorithm::HMACSHA1
        | CryptographicAlgorithm::HMACSHA224
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
        | CryptographicAlgorithm::HMACSHA3512
        | CryptographicAlgorithm::Ed448
        | CryptographicAlgorithm::CoverCrypt
        | CryptographicAlgorithm::CoverCryptBulk => {}
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::Ed25519 => {}
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::ConfigurableKEM
        | CryptographicAlgorithm::MLKEM_512
        | CryptographicAlgorithm::MLKEM_768
        | CryptographicAlgorithm::MLKEM_1024
        | CryptographicAlgorithm::X25519MLKEM768
        | CryptographicAlgorithm::X448MLKEM1024
        | CryptographicAlgorithm::MLDSA_44
        | CryptographicAlgorithm::MLDSA_65
        | CryptographicAlgorithm::MLDSA_87 => {
            // Configurable KEM, ML-KEM, hybrid KEM and ML-DSA variants are in-scope in non-FIPS mode.
            // If an allowlist is configured, they must still be explicitly allowed.
        }
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

/// Like [`validate_hashing_algorithm`] but permits SHA-1 and SHA-224 when used in a MAC
/// (HMAC) context. NIST SP 800-131A Rev. 2 Table 7 marks HMAC-SHA-1 and HMAC-SHA-224
/// as "Acceptable", so only the truly broken digests (MD2/MD4/MD5) are denied here.
fn validate_hashing_algorithm_for_mac(
    hash: HashingAlgorithm,
    whitelist: Option<&HashSet<HashingAlgorithm>>,
) -> KResult<()> {
    match hash {
        HashingAlgorithm::MD2 | HashingAlgorithm::MD4 | HashingAlgorithm::MD5 => {
            return deny(
                ErrorReason::Constraint_Violation,
                format!("Deprecated hash for MAC: {hash}"),
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

/// Like [`validate_cryptographic_parameters`] but uses [`validate_hashing_algorithm_for_mac`]
/// so that HMAC-SHA-1 and HMAC-SHA-224 are accepted in MAC/MACVerify operations.
fn validate_cryptographic_parameters_for_mac(
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
        validate_hashing_algorithm_for_mac(hash, wl.hashes.as_ref())?;
    }
    if let Some(sig) = params.digital_signature_algorithm {
        validate_signature_algorithm(sig, wl.signature_algorithms.as_ref())?;
    }
    if let Some(mode) = params.block_cipher_mode {
        validate_block_cipher_mode_typed(mode, wl.block_cipher_modes.as_ref())?;
    }
    if let Some(padding) = params.padding_method {
        validate_padding_method_typed(padding, wl.padding_methods.as_ref())?;
    }
    if let Some(mgf) = params.mask_generator {
        validate_mask_generator_typed(mgf, wl.mask_generators.as_ref())?;
    }
    if let Some(mgf_hash) = params.mask_generator_hashing_algorithm {
        validate_hashing_algorithm_for_mac(mgf_hash, wl.mgf_hashes.as_ref())?;
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

    // Curve allowlist semantics are consistent with other allowlists:
    // - `None`: no restriction (allow all recommended curves)
    // - `Some(non-empty)`: restrict to members
    // - `Some(empty)`: deny all curves
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

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // tests: a panic is the failure signal
mod tests {
    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::State,
            kmip_2_1::{
                extra::tagging::VENDOR_ID_COSMIAN, kmip_data_structures::KeyWrappingData,
                kmip_objects::Object, requests::create_symmetric_key_kmip_object,
            },
        },
        cosmian_kms_crypto::openssl::openssl_private_key_to_kmip,
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };

    use super::*;
    use crate::config::{ClapConfig, KmipAllowlistsConfig};

    fn custom_policy(allowlists: KmipAllowlistsConfig) -> KResult<ServerParams> {
        let mut conf = ClapConfig::default();
        conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
        conf.kmip_policy.allowlists = allowlists;
        ServerParams::try_from(conf)
    }

    fn curves(curves: Vec<RecommendedCurve>) -> KResult<ServerParams> {
        custom_policy(KmipAllowlistsConfig {
            curves: Some(curves),
            ..KmipAllowlistsConfig::default()
        })
    }

    /// A P-256 private key whose algorithm and curve attributes were stripped (as a
    /// `DeleteAttribute` allowed before 5.29.0 did).
    fn stripped_p256_key(key_format_type: KeyFormatType) -> KResult<ObjectWithMetadata> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut object: Object = openssl_private_key_to_kmip(&key, key_format_type, None)?;
        let attributes = object.attributes_mut()?;
        attributes.cryptographic_algorithm = None;
        attributes.cryptographic_domain_parameters = None;
        Ok(ObjectWithMetadata::new(
            "key".to_owned(),
            object,
            "owner",
            State::Active,
            Attributes::default(),
        ))
    }

    fn is_denied(result: &KResult<()>) -> bool {
        matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _))
        )
    }

    #[test]
    fn retrieved_key_curve_is_read_from_key_material() -> KResult<()> {
        let p384_only = curves(vec![RecommendedCurve::P384])?;
        let p256_only = curves(vec![RecommendedCurve::P256])?;
        for key_format_type in [KeyFormatType::TransparentECPrivateKey, KeyFormatType::PKCS8] {
            let owm = stripped_p256_key(key_format_type)?;
            let denied =
                enforce_kmip_algorithm_policy_for_retrieved_key(&p384_only, "Sign", "key", &owm);
            assert!(is_denied(&denied), "{key_format_type:?}: {denied:?}");
            enforce_kmip_algorithm_policy_for_retrieved_key(&p256_only, "Sign", "key", &owm)?;
        }
        Ok(())
    }

    #[test]
    fn retrieved_wrapped_key_with_unknown_curve_is_refused() -> KResult<()> {
        let mut owm = stripped_p256_key(KeyFormatType::PKCS8)?;
        owm.object_mut().key_block_mut()?.key_wrapping_data = Some(KeyWrappingData::default());
        let result = enforce_kmip_algorithm_policy_for_retrieved_key(
            &curves(vec![RecommendedCurve::P256])?,
            "Sign",
            "key",
            &owm,
        );
        assert!(is_denied(&result), "{result:?}");
        Ok(())
    }

    /// Stored Cryptographic Parameters stay client-editable and fill request gaps, so the
    /// block cipher mode they name is checked when the key is used.
    #[test]
    fn retrieved_key_stored_block_cipher_mode_is_checked() -> KResult<()> {
        let mut object = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[0; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Attributes::default()
            },
        )?;
        object.attributes_mut()?.cryptographic_parameters = Some(CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::ECB),
            ..CryptographicParameters::default()
        });
        let owm = ObjectWithMetadata::new(
            "key".to_owned(),
            object,
            "owner",
            State::Active,
            Attributes::default(),
        );
        let params = custom_policy(KmipAllowlistsConfig {
            block_cipher_modes: Some(vec![BlockCipherMode::GCM]),
            ..KmipAllowlistsConfig::default()
        })?;
        let result =
            enforce_kmip_algorithm_policy_for_retrieved_key(&params, "Encrypt", "key", &owm);
        assert!(is_denied(&result), "{result:?}");
        Ok(())
    }
}
