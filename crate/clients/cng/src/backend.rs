/// KMS REST client backend for the CNG KSP.
///
/// Provides a thin synchronous wrapper around the `ckms` async REST client.
/// All calls block on the shared Tokio runtime (same pattern as the PKCS#11
/// provider).  The runtime is created once and reused for every call.
use std::path::PathBuf;

use ckms::{
    config::ClientConfig,
    reexport::cosmian_kms_cli_actions::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::{
                CryptographicUsageMask, HashingAlgorithm, PaddingMethod, RevocationReason,
                RevocationReasonCode,
            },
            kmip_2_1::{
                extra::tagging::{VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
                kmip_attributes::Attributes,
                kmip_objects::Object,
                kmip_operations::{
                    CreateKeyPair, Decrypt, Destroy, Encrypt, GetAttributes, Locate, Revoke, Sign,
                    SignatureVerify,
                },
                kmip_types::{
                    AttributeReference, CryptographicAlgorithm, CryptographicDomainParameters,
                    CryptographicParameters, DigitalSignatureAlgorithm, KeyFormatType,
                    RecommendedCurve, UniqueIdentifier, ValidityIndicator,
                    VendorAttributeReference,
                },
            },
            time_normalize,
        },
        cosmian_kms_client::{ExportObjectParams, KmsClient, KmsClientError, export_object},
    },
};
use cosmian_logger::{debug, trace};
use zeroize::Zeroizing;

use crate::error::{KspError, KspResult};

/// KMS tag prefix used to identify CNG KSP keys.
pub const CNG_KSP_TAG: &str = "cng-ksp";

/// Tags used to query key by CNG name.
#[must_use]
pub fn cng_key_tag(name: &str) -> String {
    format!("{CNG_KSP_TAG}::{name}")
}

/// Shared Tokio runtime — created once, reused for every blocking KMS call.
static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("FATAL: failed to create Tokio runtime for CNG KSP: {e}");
        std::process::abort()
    })
});

/// Load a `KmsClient` from the configuration file specified, or from the
/// standard search path if `None`.
///
/// Mirrors `get_kms_client_with_path` in the PKCS#11 provider.
pub fn get_kms_client(explicit_conf: Option<PathBuf>) -> KspResult<KmsClient> {
    let config = ClientConfig::load(explicit_conf)
        .map_err(|e| KspError::Backend(format!("Failed to load ckms.toml: {e}")))?;
    KmsClient::new_with_config(config.kms_config)
        .map_err(|e: KmsClientError| KspError::Backend(format!("Failed to create KMS client: {e}")))
}

/// Locate a KMS object by its CNG key name (returns the KMS UUID).
///
/// Looks for an object carrying the tag `cng-ksp::<name>`.
pub fn locate_key_by_name(client: &KmsClient, name: &str) -> KspResult<String> {
    let tag = cng_key_tag(name);
    trace!("CNG KSP: locate_key_by_name tag={tag}");

    let resp = RUNTIME.block_on(async {
        let mut attrs = Attributes::default();
        attrs
            .set_tags(VENDOR_ID_COSMIAN, [tag.as_str()])
            .map_err(|e| KspError::Backend(e.to_string()))?;
        let locate = Locate {
            attributes: attrs,
            ..Default::default()
        };
        client
            .locate(locate)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))
    })?;

    let ids = resp.unique_identifier.unwrap_or_default();
    ids.first()
        .map(ToString::to_string)
        .ok_or_else(|| KspError::KeyNotFound(name.to_owned()))
}

/// List all CNG KSP key names and their KMS UUIDs.
pub fn list_cng_keys(client: &KmsClient) -> KspResult<Vec<(String, String)>> {
    trace!("CNG KSP: list_cng_keys");

    RUNTIME.block_on(async {
        let mut attrs = Attributes::default();
        attrs
            .set_tags(VENDOR_ID_COSMIAN, [CNG_KSP_TAG])
            .map_err(|e| KspError::Backend(e.to_string()))?;
        let locate = Locate {
            attributes: attrs,
            ..Default::default()
        };
        let response = client
            .locate(locate)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;

        let ids = response.unique_identifier.unwrap_or_default();
        // For each ID, explicitly request the vendor tag attribute so that
        // `extract_cng_name_from_tags` can find the "cng-ksp::<name>" tag.
        // (GetAttributes with attribute_reference=None excludes the tag
        //  vendor attribute by default.)
        let tag_ref = AttributeReference::Vendor(VendorAttributeReference {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_TAG.to_owned(),
        });
        let mut result = Vec::with_capacity(ids.len());
        for uid in ids {
            let uid_str = uid.to_string();
            let get_attrs = GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(uid_str.clone())),
                attribute_reference: Some(vec![tag_ref.clone()]),
            };
            if let Ok(attr_resp) = client.get_attributes(get_attrs).await {
                let name = extract_cng_name_from_tags(&attr_resp.attributes);
                result.push((name.unwrap_or_else(|| uid_str.clone()), uid_str));
            }
        }
        Ok(result)
    })
}

/// Extract the CNG key name from the vendor tags on an `Attributes`.
fn extract_cng_name_from_tags(attrs: &Attributes) -> Option<String> {
    let tags = attrs.get_tags(VENDOR_ID_COSMIAN);
    for tag in tags {
        if let Some(suffix) = tag.strip_prefix("cng-ksp::") {
            return Some(suffix.to_owned());
        }
    }
    None
}

/// Delete (destroy) a key from the KMS by its UUID.
pub fn destroy_key(client: &KmsClient, uid: &str) -> KspResult<()> {
    debug!("CNG KSP: destroy_key uid={uid}");
    RUNTIME
        .block_on(async {
            let destroy = Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                ..Default::default()
            };
            client
                .destroy(destroy)
                .await
                .map_err(|e| KspError::Backend(e.to_string()))
        })
        .map(|_| ())
}

/// Revoke a key in the KMS (required before destroy for Active keys).
pub fn revoke_key(client: &KmsClient, uid: &str) -> KspResult<()> {
    debug!("CNG KSP: revoke_key uid={uid}");
    RUNTIME
        .block_on(async {
            let revoke = Revoke {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                revocation_reason: RevocationReason {
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                    revocation_message: None,
                },
                compromise_occurrence_date: None,
                cascade: false,
            };
            client
                .revoke(revoke)
                .await
                .map_err(|e| KspError::Backend(e.to_string()))
        })
        .map(|_| ())
}

/// Fetch key attributes from the KMS.
pub fn get_key_attributes(client: &KmsClient, uid: &str) -> KspResult<Attributes> {
    RUNTIME.block_on(async {
        let get_attrs = GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: None,
        };
        let resp = client
            .get_attributes(get_attrs)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        Ok(resp.attributes)
    })
}

/// Export the public key associated with a key-pair (SPKI DER).
///
/// For RSA and EC key pairs the KMS returns the public key in PKCS#8 (SPKI)
/// format when `KeyFormatType::PKCS8` is requested.
pub fn export_public_key_spki(client: &KmsClient, uid: &str) -> KspResult<Vec<u8>> {
    debug!("CNG KSP: export_public_key_spki uid={uid}");
    RUNTIME.block_on(async {
        let params = ExportObjectParams {
            key_format_type: Some(KeyFormatType::PKCS8),
            ..ExportObjectParams::new()
        };
        let (_, obj, _) = export_object(client, uid, params)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        key_bytes_from_object(&obj)
    })
}

/// Sign a pre-hashed digest using a private key in the KMS.
///
/// `hash_alg` names the algorithm that produced `hash` (e.g. `SHA256`).
/// `padding_scheme` is `None` for ECDSA, `Some(PaddingMethod::Pss)` for RSA-PSS,
/// or `Some(PaddingMethod::Pkcs1v15)` for RSA-PKCS1.
pub fn sign_hash(
    client: &KmsClient,
    uid: &str,
    hash: &[u8],
    hash_alg: HashingAlgorithm,
    padding_scheme: Option<PaddingMethod>,
    salt_len: Option<i32>,
) -> KspResult<Vec<u8>> {
    debug!("CNG KSP: sign_hash uid={uid} hash_len={}", hash.len());
    RUNTIME.block_on(async {
        let params = CryptographicParameters {
            hashing_algorithm: Some(hash_alg),
            // Always set digital_signature_algorithm explicitly so the server
            // does not default to RSASSAPSS (which would ignore padding_method).
            digital_signature_algorithm: Some(match padding_scheme {
                Some(PaddingMethod::PSS) => DigitalSignatureAlgorithm::RSASSAPSS,
                Some(_) => {
                    // PKCS1v15 or other RSA padding
                    match hash_alg {
                        HashingAlgorithm::SHA384 => {
                            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
                        }
                        HashingAlgorithm::SHA512 => {
                            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
                        }
                        _ => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                    }
                }
                None => {
                    // EC (no padding)
                    match hash_alg {
                        HashingAlgorithm::SHA1 => DigitalSignatureAlgorithm::ECDSAWithSHA1,
                        HashingAlgorithm::SHA224 => DigitalSignatureAlgorithm::ECDSAWithSHA224,
                        HashingAlgorithm::SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
                        HashingAlgorithm::SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
                        _ => DigitalSignatureAlgorithm::ECDSAWithSHA256,
                    }
                }
            }),
            padding_method: padding_scheme,
            salt_length: salt_len,
            ..Default::default()
        };
        // Use `digested_data` for a pre-hashed input (CNG passes the digest, not the raw data)
        let sign_op = Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            cryptographic_parameters: Some(params),
            digested_data: Some(hash.to_vec()),
            ..Default::default()
        };
        let resp = client
            .sign(sign_op)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        resp.signature_data
            .ok_or_else(|| KspError::Backend("KMS sign returned no signature".to_owned()))
    })
}

/// Verify a signature on a pre-hashed digest using a public key in the KMS.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_signature(
    client: &KmsClient,
    uid: &str,
    hash: &[u8],
    signature: &[u8],
    hash_alg: HashingAlgorithm,
    padding_scheme: Option<PaddingMethod>,
    salt_len: Option<i32>,
) -> KspResult<bool> {
    debug!(
        "CNG KSP: verify_signature uid={uid} hash_len={} sig_len={}",
        hash.len(),
        signature.len()
    );
    RUNTIME.block_on(async {
        let params = CryptographicParameters {
            hashing_algorithm: Some(hash_alg),
            // Always set digital_signature_algorithm explicitly so the server
            // does not default to RSASSAPSS (which would ignore padding_method).
            digital_signature_algorithm: Some(match padding_scheme {
                Some(PaddingMethod::PSS) => DigitalSignatureAlgorithm::RSASSAPSS,
                Some(_) => {
                    // PKCS1v15 or other RSA padding
                    match hash_alg {
                        HashingAlgorithm::SHA384 => {
                            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
                        }
                        HashingAlgorithm::SHA512 => {
                            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
                        }
                        _ => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                    }
                }
                None => {
                    // EC (no padding)
                    match hash_alg {
                        HashingAlgorithm::SHA1 => DigitalSignatureAlgorithm::ECDSAWithSHA1,
                        HashingAlgorithm::SHA224 => DigitalSignatureAlgorithm::ECDSAWithSHA224,
                        HashingAlgorithm::SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
                        HashingAlgorithm::SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
                        _ => DigitalSignatureAlgorithm::ECDSAWithSHA256,
                    }
                }
            }),
            padding_method: padding_scheme,
            salt_length: salt_len,
            ..Default::default()
        };
        let verify_op = SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            cryptographic_parameters: Some(params),
            digested_data: Some(hash.to_vec()),
            signature_data: Some(signature.to_vec()),
            ..Default::default()
        };
        let resp = client
            .signature_verify(verify_op)
            .await
            .map_err(|e| KspError::Backend(format!("signature_verify error: {e}")))?;
        match resp.validity_indicator {
            Some(ValidityIndicator::Valid) => Ok(true),
            _ => Ok(false),
        }
    })
}

/// Decrypt data using a private key in the KMS.
pub fn decrypt_data(
    client: &KmsClient,
    uid: &str,
    ciphertext: &[u8],
    padding: PaddingMethod,
    hash_alg: Option<HashingAlgorithm>,
) -> KspResult<Zeroizing<Vec<u8>>> {
    debug!("CNG KSP: decrypt_data uid={uid} len={}", ciphertext.len());
    RUNTIME.block_on(async {
        let params = CryptographicParameters {
            padding_method: Some(padding),
            hashing_algorithm: hash_alg,
            ..Default::default()
        };
        let decrypt_op = Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            cryptographic_parameters: Some(params),
            data: Some(ciphertext.to_vec()),
            ..Default::default()
        };
        let resp = client
            .decrypt(decrypt_op)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        // DecryptResponse.data is already Option<Zeroizing<Vec<u8>>>
        resp.data
            .ok_or_else(|| KspError::Backend("KMS decrypt returned no data".to_owned()))
    })
}

/// Encrypt data using a public/private key in the KMS.
pub fn encrypt_data(
    client: &KmsClient,
    uid: &str,
    plaintext: &[u8],
    padding: PaddingMethod,
    hash_alg: Option<HashingAlgorithm>,
) -> KspResult<Vec<u8>> {
    debug!("CNG KSP: encrypt_data uid={uid} len={}", plaintext.len());
    RUNTIME.block_on(async {
        let params = CryptographicParameters {
            padding_method: Some(padding),
            hashing_algorithm: hash_alg,
            ..Default::default()
        };
        // Encrypt.data is Option<Zeroizing<Vec<u8>>>
        let encrypt_op = Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            cryptographic_parameters: Some(params),
            data: Some(Zeroizing::new(plaintext.to_vec())),
            ..Default::default()
        };
        let resp = client
            .encrypt(encrypt_op)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        resp.data
            .ok_or_else(|| KspError::Backend("KMS encrypt returned no data".to_owned()))
    })
}

/// Create an RSA key pair in the KMS with the given bit length and name tag,
/// and return `(private_uuid, public_uuid)`.
pub fn create_rsa_key_pair(
    client: &KmsClient,
    key_name: &str,
    bit_length: u32,
    use_for_sign: bool,
) -> KspResult<(String, String)> {
    debug!("CNG KSP: create_rsa_key_pair name={key_name} bits={bit_length}");

    let tag = cng_key_tag(key_name);
    let usage = if use_for_sign {
        CryptographicUsageMask::Sign | CryptographicUsageMask::Verify
    } else {
        CryptographicUsageMask::Decrypt | CryptographicUsageMask::Encrypt
    };

    RUNTIME.block_on(async {
        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(i32::try_from(bit_length).unwrap_or(2048)),
            cryptographic_usage_mask: Some(usage),
            // Set activation_date to the past so the key is created in Active state
            // (without it the server creates keys in PreActive state, which cannot be used).
            activation_date: Some(time_normalize().map_err(|e| KspError::Backend(e.to_string()))?),
            ..Default::default()
        };
        let mut attrs = attrs;
        attrs
            .set_tags(VENDOR_ID_COSMIAN, [CNG_KSP_TAG, tag.as_str()])
            .map_err(|e| KspError::Backend(e.to_string()))?;

        let op = CreateKeyPair {
            common_attributes: Some(attrs),
            ..Default::default()
        };
        let resp = client
            .create_key_pair(op)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        Ok((
            resp.private_key_unique_identifier.to_string(),
            resp.public_key_unique_identifier.to_string(),
        ))
    })
}

/// Create an EC key pair in the KMS with the given curve and name tag.
pub fn create_ec_key_pair(
    client: &KmsClient,
    key_name: &str,
    curve: RecommendedCurve,
) -> KspResult<(String, String)> {
    debug!("CNG KSP: create_ec_key_pair name={key_name} curve={curve:?}");

    let tag = cng_key_tag(key_name);

    RUNTIME.block_on(async {
        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                recommended_curve: Some(curve),
                ..Default::default()
            }),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            ),
            // Set activation_date to the past so the key is created in Active state
            // (without it the server creates keys in PreActive state, which cannot be used).
            activation_date: Some(time_normalize().map_err(|e| KspError::Backend(e.to_string()))?),
            ..Default::default()
        };
        let mut attrs = attrs;
        attrs
            .set_tags(VENDOR_ID_COSMIAN, [CNG_KSP_TAG, tag.as_str()])
            .map_err(|e| KspError::Backend(e.to_string()))?;

        let op = CreateKeyPair {
            common_attributes: Some(attrs),
            ..Default::default()
        };
        let resp = client
            .create_key_pair(op)
            .await
            .map_err(|e| KspError::Backend(e.to_string()))?;
        Ok((
            resp.private_key_unique_identifier.to_string(),
            resp.public_key_unique_identifier.to_string(),
        ))
    })
}

/// Extract raw key bytes (SPKI DER) from a KMS `Object`.
fn key_bytes_from_object(obj: &Object) -> KspResult<Vec<u8>> {
    obj.key_block()
        .and_then(ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_data_structures::KeyBlock::key_bytes)
        .map(|z| z.to_vec())
        .map_err(|e| KspError::Backend(e.to_string()))
}
