use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng, Nonce, RandomFixedSizeCBytes,
};
use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, Encrypt},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};

use crate::{
    crypto::symmetric::{create_symmetric_key, AesGcmSystem, KEY_LENGTH, NONCE_LENGTH},
    DecryptionSystem, EncryptionSystem,
};

#[test]
pub fn test_aes() {
    let mut rng = CsRng::from_entropy();
    let mut symmetric_key = vec![0; KEY_LENGTH];
    rng.fill_bytes(&mut symmetric_key);
    let key = create_symmetric_key(&symmetric_key, CryptographicAlgorithm::AES);
    let aes = AesGcmSystem::instantiate("blah", &key).unwrap();
    let mut data = vec![0_u8; 42];
    rng.fill_bytes(&mut data);
    let mut uid = vec![0_u8; 32];
    rng.fill_bytes(&mut uid);
    let nonce: Nonce<NONCE_LENGTH> = Nonce::new(&mut rng);
    // encrypt
    let enc_res = aes
        .encrypt(&Encrypt {
            unique_identifier: Some("blah".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce.as_bytes().to_vec()),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid.clone()),
        })
        .unwrap();
    // decrypt
    let dec_res = aes
        .decrypt(&Decrypt {
            unique_identifier: Some("blah".to_owned()),
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
