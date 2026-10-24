//! Lifecycle of hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768`) under an HSM KEK.
//! These keys are `ByteString`-only: they have no OpenSSL representation.
use std::{path::Path, sync::Arc};

use cosmian_kms_client_utils::{
    configurable_kem_utils::{KemAlgorithm, build_create_configurable_kem_keypair_request},
    reexport::cosmian_kmip::kmip_2_1::kmip_objects::{Object, ObjectType},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{
            CryptographicUsageMask, KeyWrapType, RevocationReason, RevocationReasonCode,
        },
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyValue, KeyWrappingData, KeyWrappingSpecification},
            kmip_operations::{
                Activate, CreateKeyPair, Destroy, Export, GetAttributes, Import, Operation,
                ReKeyKeyPair, Revoke,
            },
            kmip_types::{
                CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
                EncodingOption, EncryptionKeyInformation, KeyFormatType, RecommendedCurve,
                UniqueIdentifier, WrappingMethod,
            },
            requests::{
                create_pqc_key_pair_request, create_symmetric_key_kmip_object, decrypt_request,
                encrypt_request,
            },
        },
        time_normalize,
    },
    cosmian_kms_crypto::{
        crypto::{
            KeyPair, KeyPairIdentity, kem::kem_keygen, pqc::hybrid_kem::create_hybrid_kem_key_pair,
        },
        reexport::cosmian_crypto_core::bytes_ser_de::Serializable,
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::{
        hsm::{
            create_kek, delete_key, export_object, hsm_clap_config, import_object, locate_keys,
            send_message,
        },
        test_utils::get_tmp_sqlite_path,
    },
};

#[derive(Clone, Copy)]
enum Alg {
    MlKem512P256,
    MlKem768P256,
    X25519MlKem768,
    /// Pure (non hybrid) ML-KEM, stored as PKCS#8
    MlKem768,
}

impl Alg {
    /// `ConfigurableKEM` private keys default to sensitive, which denies exporting them
    /// without a user wrapping key: ask for non-sensitive keys.
    fn create_request(self, tag: &str) -> KResult<CreateKeyPair> {
        let mut request = self.base_request(tag)?;
        request.common_attributes.get_or_insert_default().sensitive = Some(false);
        Ok(request)
    }

    fn base_request(self, tag: &str) -> KResult<CreateKeyPair> {
        Ok(match self {
            Self::MlKem512P256 => build_create_configurable_kem_keypair_request(
                VENDOR_ID_COSMIAN,
                None,
                [tag],
                KemAlgorithm::MlKem512P256,
                false,
                None,
            )
            .map_err(|e| KmsError::Default(e.to_string()))?,
            Self::MlKem768P256 => build_create_configurable_kem_keypair_request(
                VENDOR_ID_COSMIAN,
                None,
                [tag],
                KemAlgorithm::MlKem768P256,
                false,
                None,
            )
            .map_err(|e| KmsError::Default(e.to_string()))?,
            Self::X25519MlKem768 => create_pqc_key_pair_request(
                VENDOR_ID_COSMIAN,
                [tag],
                CryptographicAlgorithm::X25519MLKEM768,
                false,
            )?,
            Self::MlKem768 => create_pqc_key_pair_request(
                VENDOR_ID_COSMIAN,
                [tag],
                CryptographicAlgorithm::MLKEM_768,
                false,
            )?,
        })
    }

    /// Stored algorithm, private key format, public key format
    const fn stored(self) -> (CryptographicAlgorithm, KeyFormatType, KeyFormatType) {
        match self {
            Self::MlKem512P256 | Self::MlKem768P256 => (
                CryptographicAlgorithm::ConfigurableKEM,
                KeyFormatType::ConfigurableKEMSecretKey,
                KeyFormatType::ConfigurableKEMPublicKey,
            ),
            Self::X25519MlKem768 => (
                CryptographicAlgorithm::X25519MLKEM768,
                KeyFormatType::Raw,
                KeyFormatType::Raw,
            ),
            Self::MlKem768 => (
                CryptographicAlgorithm::MLKEM_768,
                KeyFormatType::PKCS8,
                KeyFormatType::PKCS8,
            ),
        }
    }
}

pub(super) async fn test_hybrid_kem_lifecycle() -> KResult<()> {
    for alg in [Alg::MlKem512P256, Alg::MlKem768P256, Alg::X25519MlKem768] {
        Box::pin(lifecycle(alg)).await?;
    }
    Ok(())
}

async fn restart(
    owner: &str,
    kek_uuid: Uuid,
    sqlite_path: &Path,
    default_unwrap: bool,
) -> KResult<Arc<KMS>> {
    let mut clap_config = hsm_clap_config(owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.to_path_buf();
    if default_unwrap {
        clap_config.default_unwrap_type =
            Some(vec!["PrivateKey".to_owned(), "PublicKey".to_owned()]);
    }
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?,
    ))
}

/// Returns (shared secret, encapsulation)
async fn encapsulate(kms: &Arc<KMS>, owner: &str, pk_uid: &str) -> KResult<(Vec<u8>, Vec<u8>)> {
    let request = encrypt_request(pk_uid, None, Vec::new(), None, None, None)?;
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Encrypt(Box::new(request))],
    )
    .await?;
    let Operation::EncryptResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let data = response
        .data
        .clone()
        .ok_or_else(|| KmsError::ServerError("empty encapsulation data".to_owned()))?;
    if let Some(enc) = response.i_v_counter_nonce.clone() {
        // native hybrid KEM
        return Ok((data, enc));
    }
    // ConfigurableKEM: serialized (shared secret, encapsulation)
    let (secret, enc) = <(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>::deserialize(&data)
        .map_err(|e| KmsError::Default(e.to_string()))?;
    Ok((secret.to_vec(), enc.to_vec()))
}

async fn decapsulate(kms: &Arc<KMS>, owner: &str, sk_uid: &str, enc: &[u8]) -> KResult<Vec<u8>> {
    let request = decrypt_request(sk_uid, None, enc.to_vec(), None, None, None);
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Decrypt(Box::new(request))],
    )
    .await?;
    let Operation::DecryptResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    Ok(response
        .data
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("empty decapsulated secret".to_owned()))?
        .to_vec())
}

async fn assert_roundtrip(kms: &Arc<KMS>, owner: &str, pk: &str, sk: &str) -> KResult<()> {
    let (secret, enc) = encapsulate(kms, owner, pk).await?;
    assert!(!secret.is_empty());
    assert_eq!(secret, decapsulate(kms, owner, sk, &enc).await?);
    Ok(())
}

/// Imported objects are `PreActive`
async fn activate(kms: &Arc<KMS>, owner: &str, uid: &str) -> KResult<()> {
    send_message(
        kms.clone(),
        owner,
        vec![Operation::Activate(Activate {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        })],
    )
    .await?;
    Ok(())
}

async fn get_attributes(
    kms: &Arc<KMS>,
    owner: &str,
    uid: &str,
    algorithm: CryptographicAlgorithm,
) -> KResult<()> {
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::GetAttributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: None,
        })],
    )
    .await?;
    let Operation::GetAttributesResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(response.attributes.cryptographic_algorithm, Some(algorithm));
    Ok(())
}

async fn export_with(
    kms: &Arc<KMS>,
    owner: &str,
    uid: &str,
    key_wrap_type: Option<KeyWrapType>,
    key_format_type: Option<KeyFormatType>,
) -> KResult<Object> {
    Ok(kms
        .export(
            Export {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                key_format_type,
                key_compression_type: None,
                key_wrap_type,
                key_wrapping_specification: None,
            },
            &UserId::from(owner),
        )
        .await?
        .object)
}

fn uid_string(uid: &UniqueIdentifier) -> KResult<String> {
    uid.as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| KmsError::ServerError("unexpected unique identifier".to_owned()))
}

fn assert_wrapped_by(object: &Object, kek_uid: &str) -> KResult<()> {
    assert!(object.is_wrapped());
    let kek = object
        .key_block()?
        .key_wrapping_data
        .as_ref()
        .and_then(|d| d.encryption_key_information.as_ref())
        .map(|i| i.unique_identifier.clone());
    assert_eq!(kek, Some(UniqueIdentifier::TextString(kek_uid.to_owned())));
    Ok(())
}

/// Revoke then destroy `uid` alone (no cascade along the key links)
async fn revoke_and_destroy(uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let uid = UniqueIdentifier::TextString(uid.to_owned());
    send_message(
        kms.clone(),
        owner,
        vec![Operation::Revoke(Revoke {
            unique_identifier: Some(uid.clone()),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Unspecified,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        })],
    )
    .await?;
    send_message(
        kms.clone(),
        owner,
        vec![Operation::Destroy(Destroy {
            unique_identifier: Some(uid),
            remove: true,
            cascade: false,
            expected_object_type: None,
        })],
    )
    .await?;
    Ok(())
}

async fn lifecycle(alg: Alg) -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();
    let tag = Uuid::new_v4().to_string();
    let sqlite_path = get_tmp_sqlite_path();
    let (stored_algorithm, sk_format, pk_format) = alg.stored();

    // 1. Create: the server KEK wraps the new pair
    let kms = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    let kek_uid = hsm_clap_config(&owner, Some(kek_uuid))?
        .key_encryption_key
        .ok_or_else(|| KmsError::Default("Missing KEK".to_owned()))?;
    create_kek(&kek_uid, &owner, &kms).await?;
    let response = send_message(
        kms.clone(),
        &owner,
        vec![Operation::CreateKeyPair(Box::new(
            alg.create_request(&tag)?,
        ))],
    )
    .await?;
    let Operation::CreateKeyPairResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let sk = uid_string(&response.private_key_unique_identifier)?;
    let pk = uid_string(&response.public_key_unique_identifier)?;
    assert_wrapped_by(&export_object(&kms, &owner, &sk).await?, &kek_uid)?;
    assert_wrapped_by(&export_object(&kms, &owner, &pk).await?, &kek_uid)?;
    assert_roundtrip(&kms, &owner, &pk, &sk).await?;

    // 2. Restart: cold cache, the HSM unwraps
    drop(kms);
    let kms = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    assert_roundtrip(&kms, &owner, &pk, &sk).await?;
    get_attributes(&kms, &owner, &sk, stored_algorithm).await?;
    let mut attributes = Attributes::default();
    attributes.set_tags(VENDOR_ID_COSMIAN, [tag.as_str()])?;
    let located = locate_keys(&owner, &kms, Some(attributes)).await?;
    assert!(located.contains(&UniqueIdentifier::TextString(sk.clone())));
    assert!(located.contains(&UniqueIdentifier::TextString(pk.clone())));

    // 3. Export: only the stored format can be returned
    let not_wrapped = Some(KeyWrapType::NotWrapped);
    let plain_sk = export_with(&kms, &owner, &sk, not_wrapped, None).await?;
    assert!(!plain_sk.is_wrapped());
    assert_eq!(plain_sk.key_block()?.key_format_type, sk_format);
    let plain_pk = export_with(&kms, &owner, &pk, not_wrapped, None).await?;
    assert!(!plain_pk.is_wrapped());
    assert_eq!(plain_pk.key_block()?.key_format_type, pk_format);
    export_with(&kms, &owner, &sk, not_wrapped, Some(sk_format)).await?;
    export_with(&kms, &owner, &pk, not_wrapped, Some(pk_format)).await?;
    export_with(
        &kms,
        &owner,
        &sk,
        not_wrapped,
        Some(KeyFormatType::TransparentECPrivateKey),
    )
    .await
    .unwrap_err();
    let wrapped_sk = export_object(&kms, &owner, &sk).await?;
    assert!(wrapped_sk.is_wrapped());

    // 4. Import: plain objects are wrapped by the server KEK, wrapped ones are stored as-is
    let sk_imp = format!("{sk}-imp");
    let pk_imp = format!("{pk}-imp");
    let sk_impw = format!("{sk}-impw");
    import_object(&kms, &owner, &sk_imp, &plain_sk, ObjectType::PrivateKey).await?;
    import_object(&kms, &owner, &pk_imp, &plain_pk, ObjectType::PublicKey).await?;
    import_object(&kms, &owner, &sk_impw, &wrapped_sk, ObjectType::PrivateKey).await?;
    for uid in [&sk_imp, &pk_imp, &sk_impw] {
        activate(&kms, &owner, uid).await?;
        assert!(export_object(&kms, &owner, uid).await?.is_wrapped());
    }

    // 5. Restart with default_unwrap_type: reads return plaintext keys
    drop(kms);
    let kms = restart(&owner, kek_uuid, &sqlite_path, true).await?;
    assert!(!export_object(&kms, &owner, &sk).await?.is_wrapped());
    get_attributes(&kms, &owner, &sk, stored_algorithm).await?;
    assert_roundtrip(&kms, &owner, &pk_imp, &sk_imp).await?;
    let (secret, enc) = encapsulate(&kms, &owner, &pk).await?;
    assert_eq!(secret, decapsulate(&kms, &owner, &sk_impw, &enc).await?);

    // 6. ReKeyKeyPair: the replacement pair is wrapped by the server KEK
    let response = send_message(
        kms.clone(),
        &owner,
        vec![Operation::ReKeyKeyPair(Box::new(ReKeyKeyPair {
            private_key_unique_identifier: Some(UniqueIdentifier::TextString(sk.clone())),
            ..Default::default()
        }))],
    )
    .await?;
    let Operation::ReKeyKeyPairResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let sk2 = uid_string(&response.private_key_unique_identifier)?;
    let pk2 = uid_string(&response.public_key_unique_identifier)?;
    drop(kms);
    let kms = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    assert_wrapped_by(&export_object(&kms, &owner, &sk2).await?, &kek_uid)?;
    assert_roundtrip(&kms, &owner, &pk2, &sk2).await?;

    // 7. Revoke + Destroy each key on its own: a cascade follows the key links, and the
    // imported keys link to the originals.
    let all = [&sk_impw, &sk_imp, &pk_imp, &sk, &pk, &sk2, &pk2];
    for uid in all {
        revoke_and_destroy(uid, &owner, &kms).await?;
    }
    let remaining = locate_keys(&owner, &kms, None).await?;
    for uid in all {
        assert!(!remaining.contains(&UniqueIdentifier::TextString(uid.clone())));
    }
    delete_key(&kek_uid, &owner, &kms).await?;
    export_object(&kms, &owner, &sk).await.unwrap_err();
    Ok(())
}

/// Same import attributes as `ckms keys import`: activated now, usage mask from `--key-usage`.
async fn import_activated(
    kms: &Arc<KMS>,
    owner: &str,
    uid: &str,
    object: Object,
    object_type: ObjectType,
) -> KResult<()> {
    kms.import(
        Import {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            object_type,
            attributes: Attributes {
                object_type: Some(object_type),
                activation_date: Some(time_normalize()?),
                cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
                ..Default::default()
            },
            replace_existing: None,
            key_wrap_type: None,
            object,
        },
        &UserId::from(owner),
    )
    .await?;
    Ok(())
}

/// Keys created on a server without KEK, exported TTLV-wrapped by a software AES key, then
/// imported (still wrapped) in a server whose KEK is in the HSM. The software key is itself
/// wrapped by the HSM KEK on that server.
pub(super) async fn test_ttlv_wrapped_kem_import() -> KResult<()> {
    for alg in [Alg::MlKem768P256, Alg::X25519MlKem768, Alg::MlKem768] {
        Box::pin(ttlv_wrapped_import(alg)).await?;
    }
    Ok(())
}

async fn ttlv_wrapped_import(alg: Alg) -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();
    let tag = Uuid::new_v4().to_string();
    let sqlite_path = get_tmp_sqlite_path();

    let prod = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    let kek_uid = hsm_clap_config(&owner, Some(kek_uuid))?
        .key_encryption_key
        .ok_or_else(|| KmsError::Default("Missing KEK".to_owned()))?;
    create_kek(&kek_uid, &owner, &prod).await?;
    // the source server has no key encryption key
    let mut source_config = hsm_clap_config(&owner, None)?;
    source_config.db.sqlite_path = get_tmp_sqlite_path();
    let source =
        Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(source_config)?)).await?);

    // the same software AES wrapping key on both servers
    let aes = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[7_u8; 32],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    for kms in [&prod, &source] {
        import_activated(kms, &owner, "kemkek", aes.clone(), ObjectType::SymmetricKey).await?;
    }

    let response = send_message(
        source.clone(),
        &owner,
        vec![Operation::CreateKeyPair(Box::new(
            alg.create_request(&tag)?,
        ))],
    )
    .await?;
    let Operation::CreateKeyPairResponse(response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    let sk = uid_string(&response.private_key_unique_identifier)?;
    let pk = uid_string(&response.public_key_unique_identifier)?;
    assert_roundtrip(&source, &owner, &pk, &sk).await?;

    for (uid, object_type) in [(&sk, ObjectType::PrivateKey), (&pk, ObjectType::PublicKey)] {
        // what `ckms keys export --wrap-key-id kemkek -f json-ttlv` asks for
        let exported = source
            .export(
                Export {
                    unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrap_type: None,
                    key_wrapping_specification: Some(KeyWrappingSpecification {
                        wrapping_method: WrappingMethod::Encrypt,
                        encryption_key_information: Some(EncryptionKeyInformation {
                            unique_identifier: UniqueIdentifier::TextString("kemkek".to_owned()),
                            cryptographic_parameters: None,
                        }),
                        encoding_option: Some(EncodingOption::TTLVEncoding),
                        ..Default::default()
                    }),
                },
                &UserId::from(owner.as_str()),
            )
            .await?
            .object;
        assert!(exported.is_wrapped());
        import_activated(&prod, &owner, uid, exported, object_type).await?;
    }
    assert_roundtrip(&prod, &owner, &pk, &sk).await?;

    // cold cache: unwrap again from the database
    drop(prod);
    let prod = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    assert_roundtrip(&prod, &owner, &pk, &sk).await?;
    Ok(())
}

/// `ConfigurableKEM` and native hybrid keys generated client side, wrapped (TTLV) by the HSM KEK
/// with a KMIP Encrypt, and imported as already wrapped.
pub(super) async fn test_client_wrapped_kem_import() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();
    let sqlite_path = get_tmp_sqlite_path();
    let kms = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    let kek_uid = hsm_clap_config(&owner, Some(kek_uuid))?
        .key_encryption_key
        .ok_or_else(|| KmsError::Default("Missing KEK".to_owned()))?;
    create_kek(&kek_uid, &owner, &kms).await?;

    for configurable in [true, false] {
        let sk = format!("cw-{}", Uuid::new_v4());
        let pk = format!("{sk}_pk");
        let pair = client_key_pair(configurable, &sk, &pk)?;
        for (uid, object, object_type) in [
            (&sk, pair.private_key(), ObjectType::PrivateKey),
            (&pk, pair.public_key(), ObjectType::PublicKey),
        ] {
            let block = object.key_block()?;
            let plaintext = block
                .key_value
                .as_ref()
                .ok_or_else(|| KmsError::Default("no key value".to_owned()))?
                .to_ttlv_bytes(block.key_format_type)?;
            let response = send_message(
                kms.clone(),
                &owner,
                vec![Operation::Encrypt(Box::new(encrypt_request(
                    &kek_uid, None, plaintext, None, None, None,
                )?))],
            )
            .await?;
            let Operation::EncryptResponse(response) = &response[0] else {
                return Err(KmsError::ServerError("invalid response".to_owned()));
            };
            // the same layout as the server wrapping: IV || ciphertext || tag
            let wrapped = [
                response.i_v_counter_nonce.clone().unwrap_or_default(),
                response.data.clone().unwrap_or_default(),
                response
                    .authenticated_encryption_tag
                    .clone()
                    .unwrap_or_default(),
            ]
            .concat();
            let mut wrapped_object = object.clone();
            let wrapped_block = wrapped_object.key_block_mut()?;
            wrapped_block.key_value = Some(KeyValue::ByteString(Zeroizing::new(wrapped)));
            wrapped_block.key_wrapping_data = Some(KeyWrappingData {
                wrapping_method: WrappingMethod::Encrypt,
                encryption_key_information: Some(EncryptionKeyInformation {
                    unique_identifier: UniqueIdentifier::TextString(kek_uid.clone()),
                    cryptographic_parameters: None,
                }),
                mac_signature_key_information: None,
                mac_signature: None,
                iv_counter_nonce: None,
                encoding_option: Some(EncodingOption::TTLVEncoding),
            });
            import_activated(&kms, &owner, uid, wrapped_object, object_type).await?;
        }
        assert_roundtrip(&kms, &owner, &pk, &sk).await?;
    }

    // cold cache: the HSM unwraps both pairs again
    drop(kms);
    let kms = restart(&owner, kek_uuid, &sqlite_path, false).await?;
    for uid in locate_keys(&owner, &kms, None).await? {
        let uid = uid_string(&uid)?;
        if let Some(sk) = uid.strip_suffix("_pk").filter(|s| s.starts_with("cw-")) {
            assert_roundtrip(&kms, &owner, &uid, sk).await?;
        }
    }
    Ok(())
}

fn client_key_pair(configurable: bool, sk: &str, pk: &str) -> KResult<KeyPair> {
    let common = Attributes {
        activation_date: Some(time_normalize()?),
        ..Default::default()
    };
    if configurable {
        kem_keygen(
            VENDOR_ID_COSMIAN,
            sk.to_owned(),
            None,
            pk.to_owned(),
            None,
            Attributes {
                cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                    qlength: Some(256),
                    recommended_curve: Some(RecommendedCurve::P256),
                }),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                    ..Default::default()
                }),
                ..common
            },
        )
    } else {
        create_hybrid_kem_key_pair(
            CryptographicAlgorithm::X25519MLKEM768,
            KeyPairIdentity {
                vendor_id: VENDOR_ID_COSMIAN,
                private_key_uid: sk,
                public_key_uid: pk,
                common_attributes: common,
                private_key_attributes: None,
                public_key_attributes: None,
            },
            None,
        )
    }
    .map_err(|e| KmsError::Default(e.to_string()))
}
