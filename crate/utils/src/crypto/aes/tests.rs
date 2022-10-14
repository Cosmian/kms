use cosmian_crypto_base::{
    entropy::CsRng,
    symmetric_crypto::{aes_256_gcm_pure::Nonce, nonce::NonceTrait},
    typenum,
};
use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, Encrypt},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};

use super::AesGcmCipher;
use crate::{crypto::aes::create_symmetric_key, DeCipher, EnCipher};

#[test]
pub fn test_aes() {
    let mut rng = CsRng::new();
    let key = create_symmetric_key(CryptographicAlgorithm::AES, None).unwrap();
    let aes = AesGcmCipher::instantiate("blah", &key).unwrap();
    let data = rng.generate_random_bytes::<typenum::U42>();
    let uid = rng.generate_random_bytes::<typenum::U32>();
    let nonce = Nonce::new(&mut rng);
    // encrypt
    let enc_res = aes
        .encrypt(&Encrypt {
            unique_identifier: Some("blah".to_owned()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                initial_counter_value: Some(42),
                ..Default::default()
            }),
            data: Some(data.to_vec()),
            iv_counter_nonce: Some(nonce.into()),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: Some(uid.to_vec()),
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
            authenticated_encryption_additional_data: Some(uid.to_vec()),
            authenticated_encryption_tag: Some(enc_res.authenticated_encryption_tag.unwrap()),
        })
        .unwrap();

    assert_eq!(&data.to_vec(), &dec_res.data.unwrap());
}
