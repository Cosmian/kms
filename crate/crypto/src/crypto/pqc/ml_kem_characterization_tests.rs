use super::{ml_kem_decapsulate, ml_kem_encapsulate};

#[test]
fn characterization_ml_kem_768_encaps_decaps() {
    let (priv_der, pub_der, _bits) =
        crate::crypto::pqc::pqc_keygen("ML-KEM-768", None, None).unwrap();

    let (ss, ct) = ml_kem_encapsulate(&pub_der).unwrap();
    let ss_recovered = ml_kem_decapsulate(&priv_der, &ct).unwrap();
    assert_eq!(ss, ss_recovered);
    assert!(!ss.is_empty());
}
