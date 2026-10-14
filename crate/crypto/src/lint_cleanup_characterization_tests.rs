use std::thread;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{
        CryptographicParameters, DigitalSignatureAlgorithm, UniqueIdentifier, ValidityIndicator,
    },
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::crypto::anonymization::{NoiseGenerator, NumberAggregator, NumberScaler, WordMasker};
#[cfg(feature = "non-fips")]
use crate::crypto::elliptic_curves::ecies::{ecies_decrypt, ecies_encrypt};
use crate::crypto::{
    elliptic_curves::{sign::ecdsa_sign, verify::ecdsa_verify},
    rng::KmsRng,
    secret::Secret,
};

#[test]
fn characterization_secret_new_zeros() {
    let s = Secret::<32>::new();
    assert_eq!(s.len(), 32);
    for b in s.iter() {
        assert_eq!(*b, 0_u8);
    }
}

#[test]
fn characterization_secret_new_large_length() {
    let handle = thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            const SIZE: usize = 8 * 1024 * 1024;
            let secret = Secret::<SIZE>::new();
            assert_eq!(secret.len(), SIZE);
            assert_eq!(secret.first().copied(), Some(0_u8));
            assert_eq!(secret.last().copied(), Some(0_u8));
        })
        .unwrap();

    handle.join().unwrap();
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p256() {
    let rng = KmsRng::new();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let priv_pkey = PKey::from_ec_key(ec_key.clone()).unwrap();
    let pub_ec_key = EcKey::from_public_key(&group, ec_key.public_key()).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_ec_key).unwrap();

    let pt = b"lint cleanup characterization";
    let ct = ecies_encrypt(&rng, &pub_pkey, pt).unwrap();

    // compressed point on P-256 = 33 bytes, tag = 16 bytes
    assert_eq!(ct.len(), 33 + pt.len() + 16);

    let decrypted = ecies_decrypt(&priv_pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), pt.as_slice());
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p256_known_ciphertext() {
    const PRIV_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e76d8eb8b43d0a20c804ff72597a287ac360a5fd4459b802a9c99da0db4a68aba14403420004ce724760c15234b8ab482caa1a3eab17f940f6a15f4f6a9932ca74ab4f86d6c5239e2ec745b9e04783aa7c5504414f2cdcde9ea3a67ebc43f8d744dcfd0c004d";
    const CT_HEX: &str = "0309b66feacbb266c91a912013a1fa7c794ea886b3c361dbc5bc56325d13f7d32284f8c7b747f89eed5ba030c2af12e174e3ec2f3c00250d3a845b805fd3e219f9269a7d7a10ee5ffdd4fe9d582e";

    let priv_der = hex::decode(PRIV_HEX).unwrap();
    let pkey = PKey::private_key_from_pkcs8(&priv_der).unwrap();
    let ct = hex::decode(CT_HEX).unwrap();

    let decrypted = ecies_decrypt(&pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), b"lint cleanup characterization");
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p384() {
    let rng = KmsRng::new();
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let priv_pkey = PKey::from_ec_key(ec_key.clone()).unwrap();
    let pub_ec_key = EcKey::from_public_key(&group, ec_key.public_key()).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_ec_key).unwrap();

    let pt = b"lint cleanup characterization";
    let ct = ecies_encrypt(&rng, &pub_pkey, pt).unwrap();

    // compressed point on P-384 = 49 bytes, tag = 16 bytes
    assert_eq!(ct.len(), 49 + pt.len() + 16);

    let decrypted = ecies_decrypt(&priv_pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), pt.as_slice());
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p384_known_ciphertext() {
    const PRIV_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104308ce2c97a85befdab5950266b7af8e40cef7f1457aee4e195bd0b2e4852bc6520cec80a53ff9900c752a971c9ca0453d2a16403620004eec2c9e6c8a7f01d2077b5507b5bed68a7bf8fa9ce9aaf419093ede2e937081cddbc3a0240290082fd017c188c8dd5135b69628cf61bd9800e3c94c59e90a52000c63589438d2924200490af62b3e98be07ff8c72b65c4039a0fd967e280a008";
    const CT_HEX: &str = "032a35fe98fe60981f1234f866e6ffb25339e9bbfca8952320b16da87c3bbe6a5b57983040f0e47a480aa2d97f4127d2313d47c01f181232027bf6e47a80c281a583e74501dc8e07de8d6873cb5a07e574196144d8ce27edfef4b1d00bea";

    let priv_der = hex::decode(PRIV_HEX).unwrap();
    let pkey = PKey::private_key_from_pkcs8(&priv_der).unwrap();
    let ct = hex::decode(CT_HEX).unwrap();

    let decrypted = ecies_decrypt(&pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), b"lint cleanup characterization");
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p521() {
    let rng = KmsRng::new();
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let priv_pkey = PKey::from_ec_key(ec_key.clone()).unwrap();
    let pub_ec_key = EcKey::from_public_key(&group, ec_key.public_key()).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_ec_key).unwrap();

    let pt = b"lint cleanup characterization";
    let ct = ecies_encrypt(&rng, &pub_pkey, pt).unwrap();

    // compressed point on P-521 = 67 bytes, tag = 16 bytes
    assert_eq!(ct.len(), 67 + pt.len() + 16);

    let decrypted = ecies_decrypt(&priv_pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), pt.as_slice());
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_ecies_standard_curves_p521_known_ciphertext() {
    const PRIV_HEX: &str = "3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044200954b2bc41b5d7387898bf758268d158aaaa39c6e75f61740bf343e6c644679edb3ca261c23173e0943945e85621341bf9eb4510ee75010ca013098bce301bdfb6ca181890381860004017f59b4502859d4a1c0b5df160574d517f41fa0f0f27d845aef80bbd18bb51da65d592d370ced1c710e4657da4c1284df477b0179f1d53c117a55987ea7f98ba6c601c271b2b917cb70efead41a2baa085eb2cb02ca54df481a829e2503d461d7b5387c5b47bacb84c53b0d999f82e30b95a837f68cc25213affbfdb70d9e05c78280cd";
    const CT_HEX: &str = "0201d725e29e9664498ae7c869732cc5bde3bb68469fff369c637a7b759440f4c1b899c28cb87866272694496e42adc670fcc8b1dedb97ddf25034ac9f05c2d0a9bba7095ab3fb82dd387fb0494dd82a0bb30bbb3e3093c928cbf18629b48d84ba53f6a5b6f57b7649865d61b7b8b05a";

    let priv_der = hex::decode(PRIV_HEX).unwrap();
    let pkey = PKey::private_key_from_pkcs8(&priv_der).unwrap();
    let ct = hex::decode(CT_HEX).unwrap();

    let decrypted = ecies_decrypt(&pkey, &ct).unwrap();
    assert_eq!(decrypted.as_slice(), b"lint cleanup characterization");
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_word_masker() {
    let words = vec!["Secret", "DATA"];
    let masker = WordMasker::new(&words);
    let output = masker.apply("my secret data, secretive DATA!");
    assert_eq!(output, "my XXXX XXXX, secretive XXXX!");
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_number_aggregator() {
    let agg = NumberAggregator::new(2).unwrap(); // 10^2 = 100
    assert_eq!(agg.apply_on_int(-1_234_567), "-1234600");
    assert_eq!(agg.apply_on_int(0), "0");
    assert_eq!(agg.apply_on_int(999_999), "1000000");
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_number_scaler() {
    let scaler = NumberScaler::new(10.0, 2.0, 1.0, 0.0).unwrap(); // mean 10, std 2 -> z = (x-10)/2
    assert_eq!(scaler.apply_on_int(-1_234_567), -617289);
    assert_eq!(scaler.apply_on_int(0), -5);
    assert_eq!(scaler.apply_on_int(999_999), 499995);
}

#[test]
#[cfg(feature = "non-fips")]
fn characterization_noise_generator_invariants() {
    let mut noise_gen = NoiseGenerator::<f64>::new_with_bounds("Uniform", 10.0, 50.0).unwrap();
    let out = noise_gen.apply_on_int(100);
    // 100 + [10, 50] is in [110, 150]
    assert!((110..=150).contains(&out));
}

#[test]
fn characterization_ecdsa_sign_verify_roundtrip() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let priv_pkey = PKey::from_ec_key(ec_key.clone()).unwrap();
    let pub_ec_key = EcKey::from_public_key(&group, ec_key.public_key()).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_ec_key).unwrap();

    let data = b"characterization message for ecdsa";
    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString("dummy-key".to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(data.to_vec())),
        correlation_value: None,
        digested_data: None,
        final_indicator: None,
        init_indicator: None,
    };
    let sig = ecdsa_sign(&sign_req, &priv_pkey).unwrap();

    let cp = CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        ..Default::default()
    };
    let validity = ecdsa_verify(&pub_pkey, data, &sig, &cp, false).unwrap();
    assert_eq!(validity, ValidityIndicator::Valid);
}

#[test]
fn characterization_ecdsa_verify_known_signature_and_flipped_byte() {
    const PUB_SPKI_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004ce724760c15234b8ab482caa1a3eab17f940f6a15f4f6a9932ca74ab4f86d6c5239e2ec745b9e04783aa7c5504414f2cdcde9ea3a67ebc43f8d744dcfd0c004d";
    const SIG_HEX: &str = "3046022100f452dbbebd59627b42a8beda4d716e47fb1d564556fda7f951a27f1b87078b0e0221009ee8ba72d271452ab7fb0824c2417db58b1177f431995ee5bf2f41d633f268de";

    let pub_der = hex::decode(PUB_SPKI_HEX).unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    let data = b"characterization message for ecdsa";
    let sig = hex::decode(SIG_HEX).unwrap();

    let cp = CryptographicParameters {
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        ..Default::default()
    };

    // Valid signature check
    let validity = ecdsa_verify(&pub_pkey, data, &sig, &cp, false).unwrap();
    assert_eq!(validity, ValidityIndicator::Valid);

    // Flipped byte in signature yields Invalid
    let mut corrupted_sig = sig.clone();
    let last_slot = corrupted_sig.len() - 1;
    let byte_ref = corrupted_sig.get_mut(last_slot).unwrap();
    *byte_ref ^= 0xFF;

    let corrupted_validity = ecdsa_verify(&pub_pkey, data, &corrupted_sig, &cp, false).unwrap();
    assert_eq!(corrupted_validity, ValidityIndicator::Invalid);
}

#[test]
fn characterization_kms_rng_fill_bytes_and_reseed() {
    let rng = KmsRng::new();
    let mut buf = [0_u8; 32];
    rng.fill_bytes(&mut buf).unwrap();
    assert!(buf.iter().any(|&b| b != 0));

    rng.reseed(b"extra entropy for characterization test")
        .unwrap();
    let mut buf2 = [0_u8; 32];
    rng.fill_public_bytes(&mut buf2).unwrap();
    assert!(buf2.iter().any(|&b| b != 0));
}
