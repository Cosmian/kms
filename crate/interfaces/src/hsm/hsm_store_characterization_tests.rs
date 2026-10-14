//! Characterization tests pinning the behavior of `build_find_attributes`,
//! `build_keyset_attributes` and the `find` / `find_by_rotate_name` HSM store paths.

use std::{collections::HashSet, sync::Arc};

use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
};

use super::{HsmStore, build_find_attributes, build_keyset_attributes, tests::MockHsm};
use crate::{EcCurve, HsmObjectFilter, KeyMetadata, KeyType, ObjectsStore, UserId};

fn metadata(key_type: KeyType, bits: usize, curve: Option<EcCurve>) -> KeyMetadata {
    KeyMetadata {
        key_type,
        key_length_in_bits: bits,
        sensitive: false,
        id: "id".to_owned(),
        tags: HashSet::new(),
        curve,
        start_date: None,
        end_date: None,
        rotate_name: None,
        rotate_generation: None,
    }
}

/// Single call site of `build_find_attributes` (its filter parameter shape is the only thing a
/// refactor may change).
fn find_attrs(meta: &Option<KeyMetadata>, filter: HsmObjectFilter) -> Attributes {
    build_find_attributes(meta, filter)
}

fn recommended_curve(attrs: &Attributes) -> Option<RecommendedCurve> {
    attrs
        .cryptographic_domain_parameters
        .as_ref()
        .and_then(|p| p.recommended_curve)
}

#[test]
fn characterization_build_find_attributes_meta_aes() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::AesKey, 256, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(256));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::Raw));
    assert!(attrs.cryptographic_domain_parameters.is_none());
    assert!(attrs.rotate_name.is_none());
    assert!(attrs.rotate_generation.is_none());
}

#[test]
fn characterization_build_find_attributes_meta_ignores_filter() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::AesKey, 128, None)),
        HsmObjectFilter::EcPublicKey,
    );
    assert_eq!(attrs.cryptographic_length, Some(128));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::Raw));
}

#[test]
fn characterization_build_find_attributes_meta_rsa_private() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::RsaPrivateKey, 2048, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(2048));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::PKCS1));
    assert!(attrs.cryptographic_domain_parameters.is_none());
}

#[test]
fn characterization_build_find_attributes_meta_rsa_public() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::RsaPublicKey, 4096, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(4096));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::PublicKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::PKCS1));
    assert!(attrs.cryptographic_domain_parameters.is_none());
}

#[test]
fn characterization_build_find_attributes_meta_ec_private_with_curve() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::EcPrivateKey, 256, Some(EcCurve::P256))),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(256));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(
        attrs.key_format_type,
        Some(KeyFormatType::TransparentECPrivateKey)
    );
    assert_eq!(recommended_curve(&attrs), Some(RecommendedCurve::P256));
    assert!(
        attrs
            .cryptographic_domain_parameters
            .as_ref()
            .unwrap()
            .qlength
            .is_none()
    );
}

#[test]
fn characterization_build_find_attributes_meta_ec_public_with_curve() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::EcPublicKey, 384, Some(EcCurve::P384))),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(384));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::PublicKey));
    assert_eq!(
        attrs.key_format_type,
        Some(KeyFormatType::TransparentECPublicKey)
    );
    assert_eq!(recommended_curve(&attrs), Some(RecommendedCurve::P384));
}

#[test]
fn characterization_build_find_attributes_meta_ec_without_curve() {
    let private = find_attrs(
        &Some(metadata(KeyType::EcPrivateKey, 521, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(
        private.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(private.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(
        private.key_format_type,
        Some(KeyFormatType::TransparentECPrivateKey)
    );
    assert!(private.cryptographic_domain_parameters.is_none());

    let public = find_attrs(
        &Some(metadata(KeyType::EcPublicKey, 521, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(
        public.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(public.object_type, Some(ObjectType::PublicKey));
    assert_eq!(
        public.key_format_type,
        Some(KeyFormatType::TransparentECPublicKey)
    );
    assert!(public.cryptographic_domain_parameters.is_none());
}

#[test]
fn characterization_build_find_attributes_meta_huge_length_defaults_to_zero() {
    let attrs = find_attrs(
        &Some(metadata(KeyType::AesKey, usize::MAX, None)),
        HsmObjectFilter::Any,
    );
    assert_eq!(attrs.cryptographic_length, Some(0));
}

#[test]
fn characterization_build_find_attributes_no_meta_any() {
    let attrs = find_attrs(&None, HsmObjectFilter::Any);
    assert!(attrs.cryptographic_length.is_none());
    assert!(attrs.cryptographic_algorithm.is_none());
    assert!(attrs.object_type.is_none());
    assert!(attrs.key_format_type.is_none());
    assert!(attrs.cryptographic_domain_parameters.is_none());
}

#[test]
fn characterization_build_find_attributes_no_meta_aes() {
    let attrs = find_attrs(&None, HsmObjectFilter::AesKey);
    assert!(attrs.cryptographic_length.is_none());
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::Raw));
}

#[test]
fn characterization_build_find_attributes_no_meta_rsa_variants() {
    let rsa = find_attrs(&None, HsmObjectFilter::RsaKey);
    assert_eq!(
        rsa.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert!(rsa.object_type.is_none());
    assert!(rsa.key_format_type.is_none());

    let private = find_attrs(&None, HsmObjectFilter::RsaPrivateKey);
    assert_eq!(
        private.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(private.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(private.key_format_type, Some(KeyFormatType::PKCS1));

    let public = find_attrs(&None, HsmObjectFilter::RsaPublicKey);
    assert_eq!(
        public.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(public.object_type, Some(ObjectType::PublicKey));
    assert_eq!(public.key_format_type, Some(KeyFormatType::PKCS1));
}

#[test]
fn characterization_build_find_attributes_no_meta_ec_variants() {
    let ec = find_attrs(&None, HsmObjectFilter::EcKey);
    assert_eq!(ec.cryptographic_algorithm, Some(CryptographicAlgorithm::EC));
    assert!(ec.object_type.is_none());
    assert!(ec.key_format_type.is_none());

    let private = find_attrs(&None, HsmObjectFilter::EcPrivateKey);
    assert_eq!(
        private.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(private.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(
        private.key_format_type,
        Some(KeyFormatType::TransparentECPrivateKey)
    );

    let public = find_attrs(&None, HsmObjectFilter::EcPublicKey);
    assert_eq!(
        public.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(public.object_type, Some(ObjectType::PublicKey));
    assert_eq!(
        public.key_format_type,
        Some(KeyFormatType::TransparentECPublicKey)
    );
}

#[cfg(feature = "non-fips")]
#[test]
fn characterization_build_find_attributes_meta_non_fips_curves() {
    let ed = find_attrs(
        &Some(metadata(KeyType::EcPrivateKey, 256, Some(EcCurve::Ed25519))),
        HsmObjectFilter::Any,
    );
    assert_eq!(
        ed.cryptographic_algorithm,
        Some(CryptographicAlgorithm::Ed25519)
    );
    assert_eq!(recommended_curve(&ed), Some(RecommendedCurve::CURVEED25519));

    let x = find_attrs(
        &Some(metadata(KeyType::EcPublicKey, 256, Some(EcCurve::X25519))),
        HsmObjectFilter::Any,
    );
    assert_eq!(
        x.cryptographic_algorithm,
        Some(CryptographicAlgorithm::ECDH)
    );
    assert_eq!(recommended_curve(&x), Some(RecommendedCurve::CURVE25519));

    let k1 = find_attrs(
        &Some(metadata(
            KeyType::EcPrivateKey,
            256,
            Some(EcCurve::Secp256k1),
        )),
        HsmObjectFilter::Any,
    );
    assert_eq!(k1.cryptographic_algorithm, Some(CryptographicAlgorithm::EC));
    assert_eq!(recommended_curve(&k1), Some(RecommendedCurve::SECP256K1));
}

#[test]
fn characterization_build_keyset_attributes_copies_rotation_fields() {
    let mut meta = metadata(KeyType::AesKey, 256, None);
    meta.rotate_name = Some("my-keyset".to_owned());
    meta.rotate_generation = Some(7);
    let attrs = build_keyset_attributes(&meta);
    assert_eq!(attrs.rotate_name.as_deref(), Some("my-keyset"));
    assert_eq!(attrs.rotate_generation, Some(7));
    assert_eq!(attrs.cryptographic_length, Some(256));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::Raw));
}

#[test]
fn characterization_build_keyset_attributes_without_rotation_fields() {
    let attrs = build_keyset_attributes(&metadata(KeyType::RsaPublicKey, 2048, None));
    assert!(attrs.rotate_name.is_none());
    assert!(attrs.rotate_generation.is_none());
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::PublicKey));
}

fn store(mock: MockHsm) -> HsmStore {
    HsmStore::new(Arc::new(mock), &["admin".to_owned()], "cosmian", "hsm")
}

#[tokio::test]
async fn characterization_find_passes_same_filter_to_every_slot() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .return_once(|| Ok(vec![1, 2]));
    mock.expect_find()
        .withf(|_, filter| matches!(filter, HsmObjectFilter::AesKey))
        .times(2)
        .returning(|slot, _| Ok(vec![format!("key{slot}").into_bytes()]));
    mock.expect_get_key_metadata().returning(|_, _| Ok(None));
    let attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        ..Attributes::default()
    };
    let found = store(mock)
        .find(Some(&attrs), None, &UserId::from("admin"), false, "cosmian")
        .await
        .unwrap();
    assert_eq!(found.len(), 2);
    let (uid1, state1, attrs1) = found.first().unwrap();
    assert_eq!(uid1, "hsm::1::key1");
    assert_eq!(*state1, cosmian_kmip::kmip_0::kmip_types::State::Active);
    assert_eq!(
        attrs1.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs1.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs1.key_format_type, Some(KeyFormatType::Raw));
    assert!(attrs1.cryptographic_length.is_none());
    let (uid2, _, attrs2) = found.get(1).unwrap();
    assert_eq!(uid2, "hsm::2::key2");
    assert_eq!(
        attrs2.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
}

#[tokio::test]
async fn characterization_find_ec_private_filter_without_metadata() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .return_once(|| Ok(vec![9]));
    mock.expect_find()
        .withf(|slot, filter| *slot == 9 && matches!(filter, HsmObjectFilter::EcPrivateKey))
        .times(1)
        .returning(|_, _| Ok(vec![b"ec".to_vec()]));
    mock.expect_get_key_metadata().returning(|_, _| Ok(None));
    let attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    let found = store(mock)
        .find(Some(&attrs), None, &UserId::from("admin"), false, "cosmian")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    let (uid, _, out) = found.first().unwrap();
    assert_eq!(uid, "hsm::9::ec");
    assert_eq!(
        out.cryptographic_algorithm,
        Some(CryptographicAlgorithm::EC)
    );
    assert_eq!(out.object_type, Some(ObjectType::PrivateKey));
    assert_eq!(
        out.key_format_type,
        Some(KeyFormatType::TransparentECPrivateKey)
    );
}

#[tokio::test]
async fn characterization_find_attributes_from_metadata() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .return_once(|| Ok(vec![3]));
    mock.expect_find()
        .withf(|_, filter| matches!(filter, HsmObjectFilter::Any))
        .times(1)
        .returning(|_, _| Ok(vec![b"rsa".to_vec()]));
    mock.expect_get_key_metadata()
        .returning(|_, _| Ok(Some(metadata(KeyType::RsaPublicKey, 2048, None))));
    let found = store(mock)
        .find(None, None, &UserId::from("admin"), false, "cosmian")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    let (uid, _, out) = found.first().unwrap();
    assert_eq!(uid, "hsm::3::rsa");
    assert_eq!(out.cryptographic_length, Some(2048));
    assert_eq!(
        out.cryptographic_algorithm,
        Some(CryptographicAlgorithm::RSA)
    );
    assert_eq!(out.object_type, Some(ObjectType::PublicKey));
    assert_eq!(out.key_format_type, Some(KeyFormatType::PKCS1));
}

#[tokio::test]
async fn characterization_find_incompatible_filter_skips_hsm() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .return_once(|| Ok(vec![3]));
    mock.expect_find().never();
    let attrs = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    let found = store(mock)
        .find(Some(&attrs), None, &UserId::from("admin"), false, "cosmian")
        .await
        .unwrap();
    assert!(found.is_empty());
}

#[tokio::test]
async fn characterization_find_by_rotate_name_scans_all_slots_and_filters() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .return_once(|| Ok(vec![4]));
    mock.expect_find()
        .withf(|slot, filter| *slot == 4 && matches!(filter, HsmObjectFilter::Any))
        .times(1)
        .returning(|_, _| Ok(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]));
    mock.expect_get_key_metadata().returning(|_, id| {
        let mut meta = metadata(KeyType::AesKey, 256, None);
        match id {
            b"a" => {
                meta.rotate_name = Some("rot".to_owned());
                meta.rotate_generation = Some(2);
            }
            b"b" => {
                meta.rotate_name = Some("other".to_owned());
                meta.rotate_generation = Some(2);
            }
            _ => {}
        }
        Ok(Some(meta))
    });
    let results = store(mock)
        .find_by_rotate_name("rot", None, &UserId::from("admin"))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let (uid, attrs) = results.first().unwrap();
    assert_eq!(uid, "hsm::4::a");
    assert_eq!(attrs.rotate_name.as_deref(), Some("rot"));
    assert_eq!(attrs.rotate_generation, Some(2));
    assert_eq!(attrs.cryptographic_length, Some(256));
    assert_eq!(
        attrs.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(attrs.object_type, Some(ObjectType::SymmetricKey));
    assert_eq!(attrs.key_format_type, Some(KeyFormatType::Raw));
}

#[tokio::test]
async fn characterization_find_by_rotate_name_generation_filter() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list()
        .returning(|| Ok(vec![4]));
    mock.expect_find()
        .returning(|_, _| Ok(vec![b"a".to_vec(), b"b".to_vec()]));
    mock.expect_get_key_metadata().returning(|_, id| {
        let mut meta = metadata(KeyType::AesKey, 256, None);
        meta.rotate_name = Some("rot".to_owned());
        meta.rotate_generation = Some(if id == b"a" { 1 } else { 2 });
        Ok(Some(meta))
    });
    let store = store(mock);
    let user = UserId::from("admin");
    let gen2 = store
        .find_by_rotate_name("rot", Some(2), &user)
        .await
        .unwrap();
    assert_eq!(gen2.len(), 1);
    assert_eq!(gen2.first().unwrap().0, "hsm::4::b");
    let gen3 = store
        .find_by_rotate_name("rot", Some(3), &user)
        .await
        .unwrap();
    assert!(gen3.is_empty());
    let all = store.find_by_rotate_name("rot", None, &user).await.unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn characterization_find_by_rotate_name_uid_form_targets_single_slot() {
    let mut mock = MockHsm::new();
    mock.expect_get_available_slot_list().never();
    mock.expect_find()
        .withf(|slot, _| *slot == 5)
        .times(1)
        .returning(|_, _| Ok(vec![b"x".to_vec()]));
    mock.expect_get_key_metadata().returning(|_, _| {
        let mut meta = metadata(KeyType::AesKey, 128, None);
        meta.rotate_name = Some("hsm::5::keyset".to_owned());
        meta.rotate_generation = Some(1);
        Ok(Some(meta))
    });
    let results = store(mock)
        .find_by_rotate_name("hsm::5::keyset", None, &UserId::from("admin"))
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let (uid, attrs) = results.first().unwrap();
    assert_eq!(uid, "hsm::5::x");
    assert_eq!(attrs.rotate_name.as_deref(), Some("hsm::5::keyset"));
    assert_eq!(attrs.rotate_generation, Some(1));
    assert_eq!(attrs.cryptographic_length, Some(128));
}
