#[cfg(not(feature = "fips"))]
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyWrappingData, kmip_objects::Object, kmip_types::EncodingOption,
};
use cosmian_kmip::{
    kmip::kmip_types::{CryptographicAlgorithm, KeyFormatType},
    openssl::{openssl_private_key_to_kmip, openssl_public_key_to_kmip},
};
#[cfg(not(feature = "fips"))]
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use openssl::{pkey::PKey, rand::rand_bytes, rsa::Rsa};

use crate::crypto::{
    symmetric::create_symmetric_key_kmip_object,
    wrap::{unwrap_key::unwrap, wrap_key::wrap},
};
#[cfg(not(feature = "fips"))]
use crate::{
    crypto::{
        elliptic_curves::operation::create_x25519_key_pair,
        wrap::{unwrap_key::unwrap_key_block, wrap_key_block},
    },
    error::KmipUtilsError,
};

#[cfg(not(feature = "fips"))]
#[test]
fn test_wrap_unwrap() -> Result<(), KmipUtilsError> {
    // the symmetric wrapping key
    let mut sym_wrapping_key_bytes = vec![0; 32];
    rand_bytes(&mut sym_wrapping_key_bytes).unwrap();
    let sym_wrapping_key = create_symmetric_key_kmip_object(
        sym_wrapping_key_bytes.as_slice(),
        CryptographicAlgorithm::AES,
    );

    // the key to wrap
    let mut sym_key_to_wrap_bytes = vec![0; 32];
    rand_bytes(&mut sym_key_to_wrap_bytes).unwrap();
    let mut sym_key_to_wrap = create_symmetric_key_kmip_object(
        sym_key_to_wrap_bytes.as_slice(),
        CryptographicAlgorithm::AES,
    );

    let wrapping_key_pair =
        create_x25519_key_pair("wrapping_private_key_uid", "wrapping_public_key_uid")?;
    let mut key_pair_to_wrap =
        create_x25519_key_pair("private_key_to_wrap_uid", "public_key_to_wrap_uid")?;

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
) -> Result<(), KmipUtilsError> {
    let key_to_wrap_bytes = key_to_wrap.key_block()?.key_bytes()?;

    // no encoding
    {
        // wrap
        wrap_key_block(key_to_wrap.key_block_mut()?, wrapping_key, None)?;
        assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(
            key_to_wrap.key_block()?.key_wrapping_data,
            Some(Default::default())
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
    }

    // TTLV encoding
    {
        let key_wrapping_data = KeyWrappingData {
            encoding_option: Some(EncodingOption::TTLVEncoding),
            ..Default::default()
        };
        // wrap
        wrap_key_block(
            key_to_wrap.key_block_mut()?,
            wrapping_key,
            Some(key_wrapping_data),
        )?;
        assert_ne!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(
            key_to_wrap.key_block()?.key_wrapping_data,
            Some(KeyWrappingData {
                encoding_option: Some(EncodingOption::TTLVEncoding),
                ..Default::default()
            })
        );
        // unwrap
        unwrap_key_block(key_to_wrap.key_block_mut()?, unwrapping_key)?;
        assert_eq!(key_to_wrap.key_block()?.key_bytes()?, key_to_wrap_bytes);
        assert_eq!(key_to_wrap.key_block()?.key_wrapping_data, None);
    }

    Ok(())
}

#[test]
fn test_encrypt_decrypt_rfc_5649() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let mut symmetric_key = vec![0; 32];
    rand_bytes(&mut symmetric_key).unwrap();
    let wrap_key =
        create_symmetric_key_kmip_object(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

    let plaintext = b"plaintext";
    let ciphertext = wrap(&wrap_key, plaintext).unwrap();
    let decrypted_plaintext = unwrap(&wrap_key, &ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}
#[test]
#[cfg(not(feature = "fips"))]
fn test_encrypt_decrypt_rfc_ecies_x25519() {
    let wrap_key_pair = create_x25519_key_pair("sk_uid", "pk_uid").unwrap();
    let plaintext = b"plaintext";
    let ciphertext = wrap(wrap_key_pair.public_key(), plaintext).unwrap();
    let decrypted_plaintext = unwrap(wrap_key_pair.private_key(), &ciphertext).unwrap();
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
    let wrap_key_pair_pub = openssl_public_key_to_kmip(
        &PKey::from_rsa(rsa_pubkey).unwrap(),
        KeyFormatType::TransparentRSAPublicKey,
    )
    .unwrap();

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_rsa(rsa_privkey).unwrap(),
        KeyFormatType::TransparentRSAPrivateKey,
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(&wrap_key_pair_pub, plaintext).unwrap();
    let decrypted_plaintext = unwrap(&wrap_key_pair_priv, &ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}

#[cfg(feature = "fips")]
#[test]
fn test_encrypt_decrypt_rsa_bad_size() {
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
    )
    .unwrap();

    let plaintext = b"plaintext";
    let encryption_res = wrap(&wrap_key_pair_pub, plaintext);
    assert!(encryption_res.is_err());
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
    )
    .unwrap();

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey).unwrap(),
        KeyFormatType::TransparentECPrivateKey,
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(&wrap_key_pair_pub, plaintext).unwrap();
    let decrypted_plaintext = unwrap(&wrap_key_pair_priv, &ciphertext).unwrap();
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
    )
    .unwrap();

    let wrap_key_pair_priv = openssl_private_key_to_kmip(
        &PKey::from_ec_key(ec_privkey).unwrap(),
        KeyFormatType::TransparentECPrivateKey,
    )
    .unwrap();

    let plaintext = b"plaintext";
    let ciphertext = wrap(&wrap_key_pair_pub, plaintext).unwrap();
    let decrypted_plaintext = unwrap(&wrap_key_pair_priv, &ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted_plaintext[..]);
}
