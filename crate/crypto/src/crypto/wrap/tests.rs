use base64::{Engine, engine::general_purpose};
#[cfg(not(feature = "non-fips"))]
use cosmian_kmip::kmip_2_1::extra::fips::FIPS_PUBLIC_RSA_MASK;
#[cfg(feature = "non-fips")]
use cosmian_kmip::kmip_2_1::kmip_types::{CryptographicDomainParameters, RecommendedCurve};
use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask},
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_data_structures::{
            KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
        },
        kmip_objects::{Object, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, EncodingOption,
            EncryptionKeyInformation, KeyFormatType, UniqueIdentifier,
        },
        requests::create_symmetric_key_kmip_object,
    },
};
#[cfg(feature = "non-fips")]
use cosmian_logger::info;
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use openssl::{pkey::PKey, rsa::Rsa};
use zeroize::Zeroizing;

use super::{unwrap_key::unwrap, wrap_key::wrap};
#[cfg(feature = "non-fips")]
use crate::crypto::elliptic_curves::operation::create_x25519_key_pair;
#[cfg(feature = "non-fips")]
use crate::crypto::{
    KeyPairIdentity, kem::kem_keygen, pqc::hybrid_kem::create_hybrid_kem_key_pair,
};
use crate::{
    crypto::{
        KmsRng,
        wrap::{aes_gcm_decrypt, key_data_to_wrap, unwrap_key_block, wrap_object_with_key},
    },
    crypto_bail, crypto_ensure,
    error::{CryptoError, result::CryptoResult},
    openssl::{openssl_private_key_to_kmip, openssl_public_key_to_kmip},
};

fn gcm_wrapping_key(key_len: usize) -> CryptoResult<(Object, KeyWrappingData)> {
    let key_bytes = KmsRng::new().random_vec(key_len)?;
    let key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::WrapKey | CryptographicUsageMask::UnwrapKey,
            ),
            ..Default::default()
        },
    )?;
    let wrapping_data = KeyWrappingData {
        encoding_option: Some(EncodingOption::NoEncoding),
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString("gcm-kek".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Default::default()
            }),
        }),
        ..Default::default()
    };
    Ok((key, wrapping_data))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
fn test_aes_gcm_wrapped_blob_boundaries() -> CryptoResult<()> {
    for key_len in [16, 24, 32] {
        let (key, wrapping_data) = gcm_wrapping_key(key_len)?;
        let key_bytes = key.key_block()?.key_bytes()?;
        for plaintext_len in [0, 1, 32] {
            let plaintext = KmsRng::new().random_vec(plaintext_len)?;
            let wrapped = wrap(&key, &wrapping_data, &plaintext, &KmsRng::new())?;
            assert_eq!(wrapped.len(), 12 + plaintext_len + 16);
            let decrypted =
                aes_gcm_decrypt(&general_purpose::STANDARD.encode(&wrapped), &key_bytes)?;
            assert!(openssl::memcmp::eq(&decrypted, &plaintext));
            let KeyValue::Structure {
                key_material: KeyMaterial::ByteString(unwrapped),
                ..
            } = unwrap(&key, &wrapping_data, &wrapped, KeyFormatType::Raw)?
            else {
                crypto_bail!("Expected unwrapped raw key bytes");
            };
            assert!(openssl::memcmp::eq(&unwrapped, &plaintext));
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
fn test_aes_gcm_rejects_truncated_wrapped_blobs() -> CryptoResult<()> {
    let (key, wrapping_data) = gcm_wrapping_key(32)?;
    let key_bytes = key.key_block()?.key_bytes()?;
    for len in 0..28 {
        let wrapped = vec![0; len];
        assert!(matches!(
            aes_gcm_decrypt(&general_purpose::STANDARD.encode(&wrapped), &key_bytes),
            Err(CryptoError::Default(message))
                if message == "Invalid wrapped key - insufficient length."
        ));
        assert!(matches!(
            unwrap(&key, &wrapping_data, &wrapped, KeyFormatType::Raw),
            Err(CryptoError::Default(message))
                if message == "Invalid wrapped key - insufficient length."
        ));
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
fn test_no_encoding_preserves_raw_asymmetric_key_bytes() -> CryptoResult<()> {
    let bytes = KmsRng::new().random_vec(32)?;
    let key_block = KeyBlock {
        key_format_type: KeyFormatType::Raw,
        key_value: Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes.clone()),
            attributes: None,
        }),
        key_compression_type: None,
        cryptographic_algorithm: None,
        cryptographic_length: None,
        key_wrapping_data: None,
    };
    for object in [
        Object::PrivateKey(PrivateKey {
            key_block: key_block.clone(),
        }),
        Object::PublicKey(PublicKey { key_block }),
    ] {
        let data = key_data_to_wrap(
            &object,
            &KeyWrappingSpecification {
                encoding_option: Some(EncodingOption::NoEncoding),
                ..Default::default()
            },
        )?;
        assert!(openssl::memcmp::eq(&data, &bytes));
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
fn test_no_encoding_serializes_transparent_rsa_keys() -> CryptoResult<()> {
    let private_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let public_key = PKey::public_key_from_der(&private_key.public_key_to_der()?)?;
    let private_object = openssl_private_key_to_kmip(
        &private_key,
        KeyFormatType::TransparentRSAPrivateKey,
        Some(CryptographicUsageMask::UnwrapKey),
    )?;
    let public_object = openssl_public_key_to_kmip(
        &public_key,
        KeyFormatType::TransparentRSAPublicKey,
        Some(CryptographicUsageMask::WrapKey),
    )?;
    let specification = KeyWrappingSpecification {
        encoding_option: Some(EncodingOption::NoEncoding),
        ..Default::default()
    };
    let private_der = key_data_to_wrap(&private_object, &specification)?;
    let expected_private_der = Zeroizing::new(private_key.private_key_to_pkcs8()?);
    assert!(openssl::memcmp::eq(&private_der, &expected_private_der));
    let public_der = key_data_to_wrap(&public_object, &specification)?;
    assert_eq!(*public_der, public_key.public_key_to_der()?);
    Ok(())
}

#[cfg(feature = "non-fips")]
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests: a failed assertion is the failure signal"
)]
fn test_wrap_unwrap_rsa_pkcs1v15() -> CryptoResult<()> {
    use cosmian_kmip::kmip_0::kmip_types::PaddingMethod;

    let private_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let public_key = PKey::public_key_from_der(&private_key.public_key_to_der()?)?;
    let private_object = openssl_private_key_to_kmip(
        &private_key,
        KeyFormatType::TransparentRSAPrivateKey,
        Some(CryptographicUsageMask::UnwrapKey),
    )?;
    let public_object = openssl_public_key_to_kmip(
        &public_key,
        KeyFormatType::TransparentRSAPublicKey,
        Some(CryptographicUsageMask::WrapKey),
    )?;
    let wrapping_data = KeyWrappingData {
        encoding_option: Some(EncodingOption::NoEncoding),
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString("rsa-kek".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::PKCS1v15),
                ..Default::default()
            }),
        }),
        ..Default::default()
    };
    let plaintext = KmsRng::new().random_vec(32)?;
    let ciphertext = wrap(&public_object, &wrapping_data, &plaintext, &KmsRng::new())?;
    assert_eq!(ciphertext.len(), 256);
    let KeyValue::Structure {
        key_material: KeyMaterial::ByteString(unwrapped),
        ..
    } = unwrap(
        &private_object,
        &wrapping_data,
        &ciphertext,
        KeyFormatType::Raw,
    )?
    else {
        crypto_bail!("Expected unwrapped raw key bytes");
    };
    assert!(openssl::memcmp::eq(&unwrapped, &plaintext));
    Ok(())
}

#[cfg(feature = "non-fips")]
#[test]
fn test_wrap_unwrap() -> Result<(), CryptoError> {
    use cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;

    log_init(option_env!("RUST_LOG"));

    let mut sym_wrapping_key_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut sym_wrapping_key_bytes)?;
    let sym_wrapping_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        sym_wrapping_key_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    // the key to wrap
    let mut sym_key_to_wrap_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut sym_key_to_wrap_bytes)?;
    let mut sym_key_to_wrap = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        sym_key_to_wrap_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let algorithm = CryptographicAlgorithm::ECDH;
    let private_key_attributes = Attributes {
        cryptographic_usage_mask: Some(CryptographicUsageMask::UnwrapKey),
        ..Attributes::default()
    };
    let public_key_attributes = Attributes {
        cryptographic_usage_mask: Some(CryptographicUsageMask::WrapKey),
        ..Attributes::default()
    };

    let wrapping_key_pair = create_x25519_key_pair(
        VENDOR_ID_COSMIAN,
        "wrapping_private_key_uid",
        "wrapping_public_key_uid",
        &algorithm,
        Attributes::default(),
        Some(private_key_attributes.clone()),
        Some(public_key_attributes.clone()),
    )?;
    let mut key_pair_to_wrap = create_x25519_key_pair(
        VENDOR_ID_COSMIAN,
        "private_key_to_wrap_uid",
        "public_key_to_wrap_uid",
        &algorithm,
        Attributes::default(),
        Some(private_key_attributes),
        Some(public_key_attributes),
    )?;

    // wrap the symmetric key with a symmetric key
    info!("===> Wrapping symmetric key with symmetric key");
    wrap_test(&sym_wrapping_key, &sym_wrapping_key, &mut sym_key_to_wrap)?;

    // wrap the asymmetric key with a symmetric key
    info!("===> Wrapping asymmetric key with symmetric key");
    wrap_test(
        &sym_wrapping_key,
        &sym_wrapping_key,
        key_pair_to_wrap.private_key_mut(),
    )?;

    // wrap the symmetric key with an asymmetric key
    info!("===> Wrapping symmetric key with asymmetric key");
    wrap_test(
        wrapping_key_pair.public_key(),
        wrapping_key_pair.private_key(),
        &mut sym_key_to_wrap,
    )?;

    // wrap the asymmetric key with an asymmetric key
    info!("===> Wrapping asymmetric key with asymmetric key");
    wrap_test(
        wrapping_key_pair.public_key(),
        wrapping_key_pair.private_key(),
        key_pair_to_wrap.private_key_mut(),
    )?;
    Ok(())
}

#[cfg(feature = "non-fips")]
fn wrap_test(
    wrapping_key: &Object,
    unwrapping_key: &Object,
    key_to_wrap: &mut Object,
) -> Result<(), CryptoError> {
    let key_to_wrap_bytes = match key_to_wrap {
        Object::SymmetricKey(_) => key_to_wrap.key_block()?.key_bytes()?,
        _ => key_to_wrap.key_block()?.ec_raw_bytes()?,
    };

    // no encoding
    {
        // wrap
        wrap_object_with_key(
            key_to_wrap,
            wrapping_key,
            &KeyWrappingSpecification {
                encoding_option: None,
                ..Default::default()
            },
            &KmsRng::new(),
        )?;
        crypto_ensure!(
            key_to_wrap.key_block()?.wrapped_key_bytes()? != key_to_wrap_bytes,
            "wrapped bytes equal plaintext"
        );
        crypto_ensure!(
            key_to_wrap.key_block()?.key_wrapping_data == Some(KeyWrappingData::default()),
            "unexpected key wrapping data"
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        crypto_ensure!(
            match key_to_wrap {
                Object::SymmetricKey(_) => key_to_wrap.key_block()?.key_bytes()?,
                _ => key_to_wrap.key_block()?.ec_raw_bytes()?,
            } == key_to_wrap_bytes,
            "unwrapped bytes mismatch"
        );
        crypto_ensure!(
            key_to_wrap.key_block()?.key_wrapping_data.is_none(),
            "key still has wrapping data"
        );
    };

    // TTLV encoding
    {
        // wrap
        wrap_object_with_key(
            key_to_wrap,
            wrapping_key,
            &KeyWrappingSpecification {
                encoding_option: Some(EncodingOption::TTLVEncoding),
                ..Default::default()
            },
            &KmsRng::new(),
        )?;
        crypto_ensure!(
            key_to_wrap.key_block()?.wrapped_key_bytes()? != key_to_wrap_bytes,
            "wrapped bytes equal plaintext"
        );
        crypto_ensure!(
            key_to_wrap.key_block()?.key_wrapping_data
                == Some(KeyWrappingData {
                    encoding_option: Some(EncodingOption::TTLVEncoding),
                    ..Default::default()
                }),
            "unexpected key wrapping data"
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        crypto_ensure!(
            match key_to_wrap {
                Object::SymmetricKey(_) => key_to_wrap.key_block()?.key_bytes()?,
                _ => key_to_wrap.key_block()?.ec_raw_bytes()?,
            } == key_to_wrap_bytes,
            "unwrapped bytes mismatch"
        );
        crypto_ensure!(
            key_to_wrap.key_block()?.key_wrapping_data.is_none(),
            "key still has wrapping data"
        );
    };

    Ok(())
}

#[test]
fn test_encrypt_decrypt_rfc_5649() -> CryptoResult<()> {
    #[cfg(not(feature = "non-fips"))]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips")
        .map_err(|e| CryptoError::Default(format!("Failed to load FIPS provider: {e}")))?;

    let mut random_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut random_bytes)?;

    let key_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    KmsRng::new().fill_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let original_key_block = data_encryption_key.key_block()?.clone();

    wrap_object_with_key(
        &mut data_encryption_key,
        &key_encryption_key,
        &KeyWrappingSpecification::default(),
        &KmsRng::new(),
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &key_encryption_key)?;

    crypto_ensure!(
        data_encryption_key.key_block()? == &original_key_block,
        "unwrapped key block mismatch"
    );
    Ok(())
}

#[test]
fn test_wrap_unwrap_aes_gcm_all_kek_sizes() -> CryptoResult<()> {
    #[cfg(not(feature = "non-fips"))]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips")
        .map_err(|e| CryptoError::Default(format!("Failed to load FIPS provider: {e}")))?;

    for kek_len in [16, 24, 32] {
        let mut kek_bytes = vec![0; kek_len];
        KmsRng::new().fill_bytes(&mut kek_bytes)?;
        let kek = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            kek_bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?;
        let mut dek_bytes = vec![0; 32];
        KmsRng::new().fill_bytes(&mut dek_bytes)?;
        let mut dek = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            dek_bytes.as_slice(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?;
        let original_key_block = dek.key_block()?.clone();

        wrap_object_with_key(
            &mut dek,
            &kek,
            &KeyWrappingSpecification {
                encryption_key_information: Some(EncryptionKeyInformation {
                    unique_identifier: UniqueIdentifier::TextString("kek".to_owned()),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
            &KmsRng::new(),
        )?;
        let Some(KeyValue::ByteString(_)) = &dek.key_block()?.key_value else {
            crypto_bail!("Key value is not a byte string");
        };
        unwrap_key_block(dek.key_block_mut()?, &kek)?;
        crypto_ensure!(
            dek.key_block()? == &original_key_block,
            "KEK of {kek_len} bytes"
        );
    }
    Ok(())
}

#[test]
#[cfg(feature = "non-fips")]
fn test_encrypt_decrypt_rfc_ecies_x25519() -> CryptoResult<()> {
    let algorithm = CryptographicAlgorithm::ECDH;
    let private_key_attributes = Attributes {
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };
    let public_key_attributes = Attributes {
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };

    let wrap_key_pair = create_x25519_key_pair(
        VENDOR_ID_COSMIAN,
        "sk_uid",
        "pk_uid",
        &algorithm,
        Attributes::default(),
        Some(private_key_attributes),
        Some(public_key_attributes),
    )?;

    let mut random_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let original_key_block = data_encryption_key.key_block()?.clone();

    wrap_object_with_key(
        &mut data_encryption_key,
        wrap_key_pair.public_key(),
        &KeyWrappingSpecification::default(),
        &KmsRng::new(),
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(
        data_encryption_key.key_block_mut()?,
        wrap_key_pair.private_key(),
    )?;

    crypto_ensure!(
        data_encryption_key.key_block()? == &original_key_block,
        "unwrapped key block mismatch"
    );
    Ok(())
}

#[test]
fn test_encrypt_decrypt_rsa() -> CryptoResult<()> {
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    openssl::provider::Provider::load(None, "fips")
        .map_err(|e| CryptoError::Default(format!("Failed to load FIPS provider: {e}")))?;

    let rsa_privkey = Rsa::generate(4096)?;
    let rsa_pubkey =
        Rsa::from_public_components(rsa_privkey.n().to_owned()?, rsa_privkey.e().to_owned()?)?;
    #[cfg(not(feature = "non-fips"))]
    let crypto_usage_mask = Some(FIPS_PUBLIC_RSA_MASK);
    #[cfg(feature = "non-fips")]
    let crypto_usage_mask = Some(CryptographicUsageMask::Unrestricted);

    let mut wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_rsa(rsa_pubkey)?,
        KeyFormatType::TransparentRSAPublicKey,
        crypto_usage_mask,
    )?;

    let mut wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_rsa(rsa_privkey)?,
        KeyFormatType::TransparentRSAPrivateKey,
        crypto_usage_mask,
    )?;

    wrap_key_pair_pub.attributes_mut()?.cryptographic_usage_mask =
        Some(CryptographicUsageMask::WrapKey);

    wrap_key_pair_priv
        .attributes_mut()?
        .cryptographic_usage_mask = Some(CryptographicUsageMask::UnwrapKey);

    let mut random_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let original_key_block = data_encryption_key.key_block()?.clone();

    wrap_object_with_key(
        &mut data_encryption_key,
        &wrap_key_pair_pub,
        &KeyWrappingSpecification::default(),
        &KmsRng::new(),
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    crypto_ensure!(
        data_encryption_key.key_block()? == &original_key_block,
        "unwrapped key block mismatch"
    );
    Ok(())
}

#[test]
#[cfg(feature = "non-fips")]
fn test_encrypt_decrypt_ec_p192() -> CryptoResult<()> {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1)?;

    let ec_privkey = EcKey::generate(&curve)?;
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key())?;

    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_ec_key(ec_pubkey)?,
        KeyFormatType::TransparentECPublicKey,
        Some(CryptographicUsageMask::Unrestricted),
    )?;

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey)?,
        KeyFormatType::TransparentECPrivateKey,
        Some(CryptographicUsageMask::Unrestricted),
    )?;

    let mut random_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let original_key_block = data_encryption_key.key_block()?.clone();

    wrap_object_with_key(
        &mut data_encryption_key,
        &wrap_key_pair_pub,
        &KeyWrappingSpecification::default(),
        &KmsRng::new(),
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    crypto_ensure!(
        data_encryption_key.key_block()? == &original_key_block,
        "unwrapped key block mismatch"
    );
    Ok(())
}

#[test]
#[cfg(feature = "non-fips")]
fn test_encrypt_decrypt_ec_p384() -> CryptoResult<()> {
    let curve = EcGroup::from_curve_name(Nid::SECP384R1)?;

    let ec_privkey = EcKey::generate(&curve)?;
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key())?;

    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_ec_key(ec_pubkey)?,
        KeyFormatType::TransparentECPublicKey,
        Some(CryptographicUsageMask::Unrestricted),
    )?;

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey)?,
        KeyFormatType::TransparentECPrivateKey,
        Some(CryptographicUsageMask::Unrestricted),
    )?;

    let mut random_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let original_key_block = data_encryption_key.key_block()?.clone();

    wrap_object_with_key(
        &mut data_encryption_key,
        &wrap_key_pair_pub,
        &KeyWrappingSpecification::default(),
        &KmsRng::new(),
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    crypto_ensure!(
        data_encryption_key.key_block()? == &original_key_block,
        "unwrapped key block mismatch"
    );
    Ok(())
}

/// ByteString-only asymmetric keys (`ConfigurableKEM`, native hybrid KEM) have no OpenSSL
/// representation: they must wrap/unwrap as raw bytes (`NoEncoding`) and as TTLV.
#[cfg(feature = "non-fips")]
#[test]
fn test_wrap_unwrap_byte_string_kem_keys() -> CryptoResult<()> {
    let mut sym_wrapping_key_bytes = vec![0; 32];
    KmsRng::new().fill_bytes(&mut sym_wrapping_key_bytes)?;
    let sym_key = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        sym_wrapping_key_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let common = Attributes {
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            qlength: Some(256),
            recommended_curve: Some(RecommendedCurve::P256),
        }),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut configurable = kem_keygen(
        VENDOR_ID_COSMIAN,
        "dk".to_owned(),
        None,
        "ek".to_owned(),
        None,
        &common,
    )?;
    let mut native = create_hybrid_kem_key_pair(
        CryptographicAlgorithm::X25519MLKEM768,
        KeyPairIdentity {
            vendor_id: VENDOR_ID_COSMIAN,
            private_key_uid: "sk",
            public_key_uid: "pk",
            common_attributes: Attributes::default(),
            private_key_attributes: None,
            public_key_attributes: None,
        },
        None,
    )?;

    for encoding in [EncodingOption::NoEncoding, EncodingOption::TTLVEncoding] {
        for i in 0..4 {
            let pair = if i < 2 {
                &mut configurable
            } else {
                &mut native
            };
            let obj = if i % 2 == 0 {
                pair.private_key_mut()
            } else {
                pair.public_key_mut()
            };
            let bytes = obj.key_block()?.key_bytes()?;
            let format = obj.key_block()?.key_format_type;
            wrap_object_with_key(
                obj,
                &sym_key,
                &KeyWrappingSpecification {
                    encoding_option: Some(encoding),
                    ..Default::default()
                },
                &KmsRng::new(),
            )?;
            crypto_ensure!(obj.is_wrapped(), "{encoding:?} #{i} not wrapped");
            unwrap_key_block(obj.key_block_mut()?, &sym_key)?;
            crypto_ensure!(obj.key_block()?.key_bytes()? == bytes, "{encoding:?} #{i}");
            crypto_ensure!(
                obj.key_block()?.key_format_type == format,
                "{encoding:?} #{i} format"
            );
            crypto_ensure!(
                obj.key_block()?.key_wrapping_data.is_none(),
                "{encoding:?} #{i} still wrapped"
            );
        }
    }
    Ok(())
}
