use openssl::rand::rand_bytes;

use crate::{
    crypto::{
        symmetric::{
            create_symmetric_key_kmip_object, AesGcmSystem, AES_256_GCM_IV_LENGTH,
            AES_256_GCM_KEY_LENGTH,
        },
        DecryptionSystem, EncryptionSystem,
    },
    kmip::{
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
};

#[test]
pub fn test_aes() {
    #[cfg(feature = "fips")]
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let mut symmetric_key = vec![0; AES_256_GCM_KEY_LENGTH];
    rand_bytes(&mut symmetric_key).unwrap();
    let key = create_symmetric_key_kmip_object(&symmetric_key, CryptographicAlgorithm::AES);
    let aes = AesGcmSystem::instantiate("blah", &key).unwrap();
    let mut data = vec![0_u8; 42];
    rand_bytes(&mut data).unwrap();
    let mut uid = vec![0_u8; 32];
    rand_bytes(&mut uid).unwrap();

    let mut nonce = vec![0u8; AES_256_GCM_IV_LENGTH];
    rand_bytes(&mut nonce).unwrap();

    // encrypt
    let enc_res = aes
        .encrypt(&Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString("blah".to_owned())),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid.clone()),
        })
        .unwrap();
    // decrypt
    let dec_res = aes
        .decrypt(&Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString("blah".to_owned())),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(enc_res.data.unwrap()),
            iv_counter_nonce: Some(enc_res.iv_counter_nonce.unwrap()),
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid.clone()),
            authenticated_encryption_tag: Some(enc_res.authenticated_encryption_tag.unwrap()),
        })
        .unwrap();

    assert_eq!(&data.clone(), &dec_res.data.unwrap());
}
