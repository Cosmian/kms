#[cfg(not(feature = "fips"))]
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use openssl::{pkey::PKey, rand::rand_bytes, rsa::Rsa};

#[cfg(feature = "fips")]
use crate::crypto::rsa::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK};
#[cfg(not(feature = "fips"))]
use crate::kmip::{
    kmip_data_structures::KeyWrappingSpecification, kmip_objects::Object,
    kmip_types::EncodingOption,
};
#[cfg(not(feature = "fips"))]
use crate::{
    crypto::{
        elliptic_curves::operation::create_x25519_key_pair,
        wrap::{unwrap_key::unwrap_key_block, wrap_key_block},
    },
    error::KmipError,
};
use crate::{
    crypto::{
        symmetric::create_symmetric_key_kmip_object,
        wrap::{unwrap_key::unwrap, wrap_key::wrap},
    },
    error::result::KmipResult,
    kmip::{
        kmip_data_structures::KeyWrappingData,
        kmip_types::{CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType},
    },
    openssl::{openssl_private_key_to_kmip, openssl_public_key_to_kmip},
};

#[cfg(not(feature = "fips"))]
#[test]
fn test_wrap_unwrap() -> Result<(), KmipError> {
    // the symmetric wrapping key

    let mut sym_wrapping_key_bytes = vec![0; 32];
    rand_bytes(&mut sym_wrapping_key_bytes).unwrap();
    let sym_wrapping_key = create_symmetric_key_kmip_object(
        sym_wrapping_key_bytes.as_slice(),
        CryptographicAlgorithm::AES,
    )?;

    // the key to wrap
    let mut sym_key_to_wrap_bytes = vec![0; 32];
    rand_bytes(&mut sym_key_to_wrap_bytes).unwrap();
    let mut sym_key_to_wrap = create_symmetric_key_kmip_object(
        sym_key_to_wrap_bytes.as_slice(),
        CryptographicAlgorithm::AES,
    )?;

    let algorithm = Some(CryptographicAlgorithm::EC);
    let private_key_mask_wp = Some(CryptographicUsageMask::UnwrapKey);
    let public_key_mask_wp = Some(CryptographicUsageMask::WrapKey);

    let private_key_mask = Some(CryptographicUsageMask::Unrestricted);
    let public_key_mask = Some(CryptographicUsageMask::Unrestricted);

    let wrapping_key_pair = create_x25519_key_pair(
        "wrapping_private_key_uid",
        "wrapping_public_key_uid",
        algorithm,
        private_key_mask_wp,
        public_key_mask_wp,
    )?;
    let mut key_pair_to_wrap = create_x25519_key_pair(
        "private_key_to_wrap_uid",
        "public_key_to_wrap_uid",
        algorithm,
        private_key_mask,
        public_key_mask,
    )?;

    // wrap the symmetric key with a symmetric key
    wrap_test(&sym_wrapping_key, &sym_wrapping_key, &mut sym_key_to_wrap)?;
    // wrap the asymmetric key with a symmetric key
    wrap_test(
        &sym_wrapping_key,
        &sym_wrapping_key,
        key_pair_to_wrap.private_key_mut(),
    )?;
    // wrap the symmetric key with an asymmetric key
    wrap_test(
        wrapping_key_pair.public_key(),
        wrapping_key_pair.private_key(),
        &mut sym_key_to_wrap,
    )?;
    // wrap the asymmetric key with an asymmetric key
    wrap_test(
        wrapping_key_pair.public_key(),
        wrapping_key_pair.private_key(),
        key_pair_to_wrap.private_key_mut(),
    )?;
    Ok(())
}

#[cfg(not(feature = "fips"))]
fn wrap_test(
    wrapping_key: &Object,
    unwrapping_key: &Object,
    key_to_wrap: &mut Object,
) -> Result<(), KmipError> {
    let key_to_wrap_bytes = key_to_wrap.key_block()?.key_bytes()?;

    // no encoding
    {
        // wrap
        wrap_key_block(
            key_to_wrap.key_block_mut()?,
            wrapping_key,
            &KeyWrappingSpecification {
                encoding_option: None,
                ..Default::default()
            },
        )?;
        assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(
            key_to_wrap.key_block()?.key_wrapping_data,
            Some(Box::default())
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
    }

    // TTLV encoding
    {
        // wrap
        wrap_key_block(
            key_to_wrap.key_block_mut()?,
            wrapping_key,
            &KeyWrappingSpecification {
                encoding_option: Some(EncodingOption::TTLVEncoding),
                ..Default::default()
            },
        )?;
        assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(
            key_to_wrap.key_block()?.key_wrapping_data,
            Some(Box::new(KeyWrappingData {
                encoding_option: Some(EncodingOption::TTLVEncoding),
                ..Default::default()
            }))
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
    }

    Ok(())
}

#[test]
fn test_encrypt_decrypt_rfc_5649() -> KmipResult<()> {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let mut symmetric_key = vec![0; 32];
    rand_bytes(&mut symmetric_key).unwrap();
    let wrap_key =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES)?;

    let plaintext = b"plaintext";
    let ciphertext = wrap(&wrap_key, &KeyWrappingData::default(), plaintext, None).unwrap();
    let decrypted_plaintext =
        unwrap(&wrap_key, &KeyWrappingData::default(), &ciphertext, None).unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
    Ok(())
}
#[test]
#[cfg(not(feature = "fips"))]
fn test_encrypt_decrypt_rfc_ecies_x25519() {
    let algorithm = Some(CryptographicAlgorithm::EC);
    let private_key_mask = Some(CryptographicUsageMask::Unrestricted);
    let public_key_mask = Some(CryptographicUsageMask::Unrestricted);

    let wrap_key_pair = create_x25519_key_pair(
        "sk_uid",
        "pk_uid",
        algorithm,
        private_key_mask,
        public_key_mask,
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(
        wrap_key_pair.public_key(),
        &KeyWrappingData::default(),
        plaintext,
        Some(&[]),
    )
    .unwrap();
    let decrypted_plaintext = unwrap(
        wrap_key_pair.private_key(),
        &KeyWrappingData::default(),
        &ciphertext,
        None,
    )
    .unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}

#[test]
fn test_encrypt_decrypt_rsa() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let rsa_privkey = Rsa::generate(2048).unwrap();
    let rsa_pubkey = Rsa::from_public_components(
        rsa_privkey.n().to_owned().unwrap(),
        rsa_privkey.e().to_owned().unwrap(),
    )
    .unwrap();
    let mut wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_rsa(rsa_pubkey).unwrap(),
        KeyFormatType::TransparentRSAPublicKey,
        #[cfg(feature = "fips")]
        Some(FIPS_PUBLIC_RSA_MASK),
        #[cfg(not(feature = "fips"))]
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    let mut wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_rsa(rsa_privkey).unwrap(),
        KeyFormatType::TransparentRSAPrivateKey,
        #[cfg(feature = "fips")]
        Some(FIPS_PRIVATE_RSA_MASK),
        #[cfg(not(feature = "fips"))]
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    wrap_key_pair_pub
        .attributes_mut()
        .unwrap()
        .cryptographic_usage_mask = Some(CryptographicUsageMask::WrapKey);

    wrap_key_pair_priv
        .attributes_mut()
        .unwrap()
        .cryptographic_usage_mask = Some(CryptographicUsageMask::UnwrapKey);

    let plaintext = b"plaintext";
    let ciphertext = wrap(
        &wrap_key_pair_pub,
        &KeyWrappingData::default(),
        plaintext,
        None,
    )
    .unwrap();
    let decrypted_plaintext = unwrap(
        &wrap_key_pair_priv,
        &KeyWrappingData::default(),
        &ciphertext,
        None,
    )
    .unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}

#[cfg(feature = "fips")]
#[test]
fn test_encrypt_decrypt_no_rsa_1024_in_fips() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let rsa_privkey = Rsa::generate(1024).unwrap();
    let rsa_pubkey = Rsa::from_public_components(
        rsa_privkey.n().to_owned().unwrap(),
        rsa_privkey.e().to_owned().unwrap(),
    )
    .unwrap();
    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_rsa(rsa_pubkey).unwrap(),
        KeyFormatType::TransparentRSAPublicKey,
        Some(FIPS_PUBLIC_RSA_MASK),
    )
    .unwrap();

    let plaintext = b"plaintext";
    let encryption_res = wrap(
        &wrap_key_pair_pub,
        &KeyWrappingData::default(),
        plaintext,
        None,
    );
    encryption_res.unwrap_err();
}

#[test]
#[cfg(not(feature = "fips"))]
fn test_encrypt_decrypt_ec_p192() {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1).unwrap();

    let ec_privkey = EcKey::generate(&curve).unwrap();
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key()).unwrap();

    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_ec_key(ec_pubkey).unwrap(),
        KeyFormatType::TransparentECPublicKey,
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey).unwrap(),
        KeyFormatType::TransparentECPrivateKey,
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(
        &wrap_key_pair_pub,
        &KeyWrappingData::default(),
        plaintext,
        Some(&[]),
    )
    .unwrap();
    let decrypted_plaintext = unwrap(
        &wrap_key_pair_priv,
        &KeyWrappingData::default(),
        &ciphertext,
        None,
    )
    .unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}

#[test]
#[cfg(not(feature = "fips"))]
fn test_encrypt_decrypt_ec_p384() {
    let curve = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();

    let ec_privkey = EcKey::generate(&curve).unwrap();
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key()).unwrap();

    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_ec_key(ec_pubkey).unwrap(),
        KeyFormatType::TransparentECPublicKey,
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey).unwrap(),
        KeyFormatType::TransparentECPrivateKey,
        Some(CryptographicUsageMask::Unrestricted),
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(
        &wrap_key_pair_pub,
        &KeyWrappingData::default(),
        plaintext,
        Some(&[]),
    )
    .unwrap();
    let decrypted_plaintext = unwrap(
        &wrap_key_pair_priv,
        &KeyWrappingData::default(),
        &ciphertext,
        None,
    )
    .unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}
