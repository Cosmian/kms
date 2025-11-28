#[cfg(not(feature = "non-fips"))]
use cosmian_kmip::kmip_2_1::extra::fips::FIPS_PUBLIC_RSA_MASK;
#[cfg(feature = "non-fips")]
use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyWrappingData, kmip_objects::Object, kmip_types::EncodingOption,
};
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyValue, KeyWrappingSpecification},
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
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
use openssl::{pkey::PKey, rand::rand_bytes, rsa::Rsa};

#[cfg(feature = "non-fips")]
use crate::crypto::elliptic_curves::operation::create_x25519_key_pair;
use crate::{
    crypto::wrap::{unwrap_key_block, wrap_object_with_key},
    crypto_bail,
    error::{CryptoError, result::CryptoResult},
    openssl::{openssl_private_key_to_kmip, openssl_public_key_to_kmip},
};

#[cfg(feature = "non-fips")]
#[test]
fn test_wrap_unwrap() -> Result<(), CryptoError> {
    use cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;

    log_init(option_env!("RUST_LOG"));

    let mut sym_wrapping_key_bytes = vec![0; 32];
    rand_bytes(&mut sym_wrapping_key_bytes)?;
    let sym_wrapping_key = create_symmetric_key_kmip_object(
        sym_wrapping_key_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    // the key to wrap
    let mut sym_key_to_wrap_bytes = vec![0; 32];
    rand_bytes(&mut sym_key_to_wrap_bytes)?;
    let mut sym_key_to_wrap = create_symmetric_key_kmip_object(
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
        "wrapping_private_key_uid",
        "wrapping_public_key_uid",
        &algorithm,
        Attributes::default(),
        Some(private_key_attributes.clone()),
        Some(public_key_attributes.clone()),
    )?;
    let mut key_pair_to_wrap = create_x25519_key_pair(
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
        )?;
        assert_ne!(
            key_to_wrap.key_block()?.wrapped_key_bytes()?,
            key_to_wrap_bytes
        );
        assert!(key_to_wrap.key_block()?.key_wrapping_data == Some(KeyWrappingData::default()));
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(
            match key_to_wrap {
                Object::SymmetricKey(_) => key_to_wrap.key_block()?.key_bytes()?,
                _ => key_to_wrap.key_block()?.ec_raw_bytes()?,
            },
            key_to_wrap_bytes
        );
        assert!(key_to_wrap.key_block()?.key_wrapping_data.is_none());
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
        )?;
        assert_ne!(
            key_to_wrap.key_block()?.wrapped_key_bytes()?,
            key_to_wrap_bytes
        );
        assert!(
            key_to_wrap.key_block()?.key_wrapping_data
                == Some(KeyWrappingData {
                    encoding_option: Some(EncodingOption::TTLVEncoding),
                    ..Default::default()
                })
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(
            match key_to_wrap {
                Object::SymmetricKey(_) => key_to_wrap.key_block()?.key_bytes()?,
                _ => key_to_wrap.key_block()?.ec_raw_bytes()?,
            },
            key_to_wrap_bytes
        );
        assert!(key_to_wrap.key_block()?.key_wrapping_data.is_none());
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
    rand_bytes(&mut random_bytes)?;

    let key_encryption_key = create_symmetric_key_kmip_object(
        random_bytes.as_slice(),
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    rand_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
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
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &key_encryption_key)?;

    assert!(data_encryption_key.key_block()? == &original_key_block);
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
        "sk_uid",
        "pk_uid",
        &algorithm,
        Attributes::default(),
        Some(private_key_attributes),
        Some(public_key_attributes),
    )?;

    let mut random_bytes = vec![0; 32];
    rand_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
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
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(
        data_encryption_key.key_block_mut()?,
        wrap_key_pair.private_key(),
    )?;

    assert!(data_encryption_key.key_block()? == &original_key_block);
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
    rand_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
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
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    assert!(data_encryption_key.key_block()? == &original_key_block);
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
    rand_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
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
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    assert!(data_encryption_key.key_block()? == &original_key_block);
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
    rand_bytes(&mut random_bytes)?;
    let mut data_encryption_key = create_symmetric_key_kmip_object(
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
    )?;
    let Some(KeyValue::ByteString(_ciphertext)) = &data_encryption_key.key_block()?.key_value
    else {
        crypto_bail!("Key value is not a byte string");
    };
    unwrap_key_block(data_encryption_key.key_block_mut()?, &wrap_key_pair_priv)?;

    assert!(data_encryption_key.key_block()? == &original_key_block);
    Ok(())
}
