#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
        ValidityIndicator,
    },
};
use cosmian_kms_crypto::crypto::{
    elliptic_curves::verify::{ecdsa_verify, ed25519_verify},
    rsa::verify::rsa_verify,
};
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::Signer,
}; // keep items at top to satisfy clippy::items-after-statements

fn sha256(data: &[u8]) -> Vec<u8> {
    use openssl::sha::sha256;
    sha256(data).to_vec()
}

#[test]
fn ed25519_verify_basic() {
    let pkey = match PKey::generate_ed25519() {
        Ok(k) => k,
        Err(e) => panic!("ed25519 gen: {e}"),
    };
    let data = b"hello world";
    let mut signer = match Signer::new_without_digest(&pkey) {
        Ok(s) => s,
        Err(e) => panic!("signer init: {e}"),
    };
    let sig = match signer.sign_oneshot_to_vec(data) {
        Ok(s) => s,
        Err(e) => panic!("sign ed25519: {e}"),
    };
    let pub_pem = match pkey.public_key_to_pem() {
        Ok(p) => p,
        Err(e) => panic!("pub pem: {e}"),
    };
    let pubkey = match PKey::public_key_from_pem(&pub_pem) {
        Ok(k) => k,
        Err(e) => panic!("pub from pem: {e}"),
    };
    let res = match ed25519_verify(&pubkey, data, &sig) {
        Ok(v) => v,
        Err(e) => panic!("verify ed25519: {e}"),
    };
    assert_eq!(res, ValidityIndicator::Valid);
}

#[test]
fn rsa_pkcs1_verify_basic() {
    let rsa = match Rsa::generate(2048) {
        Ok(r) => r,
        Err(e) => panic!("rsa gen: {e}"),
    };
    let pkey = match PKey::from_rsa(rsa) {
        Ok(k) => k,
        Err(e) => panic!("pkey from rsa: {e}"),
    };
    let data = b"hello rsa";
    let _digest = sha256(data);
    let mut signer = match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(s) => s,
        Err(e) => panic!("signer init: {e}"),
    };
    if let Err(e) = signer.set_rsa_padding(Padding::PKCS1) {
        panic!("set padding: {e}");
    }
    if let Err(e) = signer.update(data) {
        panic!("update: {e}");
    }
    let _sig = match signer.sign_to_vec() {
        Ok(s) => s,
        Err(e) => panic!("sign: {e}"),
    };
    let pub_pem = match pkey.public_key_to_pem() {
        Ok(p) => p,
        Err(e) => panic!("pub pem: {e}"),
    };
    let pubkey = match PKey::public_key_from_pem(&pub_pem) {
        Ok(k) => k,
        Err(e) => panic!("pub from pem: {e}"),
    };
    let cp = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
        ..Default::default()
    };
    // Pre-digested path
    let mut signer2 = match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(s) => s,
        Err(e) => panic!("signer init: {e}"),
    };
    if let Err(e) = signer2.set_rsa_padding(Padding::PKCS1) {
        panic!("set padding: {e}");
    }
    if let Err(e) = signer2.update(data) {
        panic!("update: {e}");
    }
    let sig2 = match signer2.sign_to_vec() {
        Ok(s) => s,
        Err(e) => panic!("sign: {e}"),
    };
    let res_predig = match rsa_verify(&pubkey, data, &sig2, &cp, false) {
        Ok(v) => v,
        Err(e) => panic!("verify rsa pkcs1: {e}"),
    };
    assert_eq!(res_predig, ValidityIndicator::Valid);
}

#[test]
fn rsa_pss_verify_basic() {
    let rsa = match Rsa::generate(2048) {
        Ok(r) => r,
        Err(e) => panic!("rsa gen: {e}"),
    };
    let pkey = match PKey::from_rsa(rsa) {
        Ok(k) => k,
        Err(e) => panic!("pkey from rsa: {e}"),
    };
    let data = b"hello pss";
    let mut signer = match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(s) => s,
        Err(e) => panic!("signer init: {e}"),
    };
    if let Err(e) = signer.set_rsa_padding(Padding::PKCS1_PSS) {
        panic!("set padding: {e}");
    }
    if let Err(e) = signer.update(data) {
        panic!("update: {e}");
    }
    let sig = match signer.sign_to_vec() {
        Ok(s) => s,
        Err(e) => panic!("sign: {e}"),
    };
    let pub_pem = match pkey.public_key_to_pem() {
        Ok(p) => p,
        Err(e) => panic!("pub pem: {e}"),
    };
    let pubkey = match PKey::public_key_from_pem(&pub_pem) {
        Ok(k) => k,
        Err(e) => panic!("pub from pem: {e}"),
    };
    let cp = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::PSS),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        mask_generator_hashing_algorithm: Some(HashingAlgorithm::SHA256),
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
        ..Default::default()
    };
    let res = match rsa_verify(&pubkey, data, &sig, &cp, false) {
        Ok(v) => v,
        Err(e) => panic!("verify rsa pss: {e}"),
    };
    assert_eq!(res, ValidityIndicator::Valid);
}

#[test]
fn ecdsa_verify_basic() {
    let group = match openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1) {
        Ok(g) => g,
        Err(e) => panic!("group: {e}"),
    };
    let group_key = match EcKey::generate(&group) {
        Ok(k) => k,
        Err(e) => panic!("ec gen: {e}"),
    };
    let pkey = match PKey::from_ec_key(group_key) {
        Ok(k) => k,
        Err(e) => panic!("pkey ec: {e}"),
    };
    let data = b"hello ecdsa";
    let mut signer = match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(s) => s,
        Err(e) => panic!("signer init: {e}"),
    };
    if let Err(e) = signer.update(data) {
        panic!("update: {e}");
    }
    let sig = match signer.sign_to_vec() {
        Ok(s) => s,
        Err(e) => panic!("sign: {e}"),
    };
    let pub_pem = match pkey.public_key_to_pem() {
        Ok(p) => p,
        Err(e) => panic!("pub pem: {e}"),
    };
    let pubkey = match PKey::public_key_from_pem(&pub_pem) {
        Ok(k) => k,
        Err(e) => panic!("pub from pem: {e}"),
    };
    let cp = CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
        hashing_algorithm: Some(HashingAlgorithm::SHA256),
        digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
        ..Default::default()
    };
    let res = match ecdsa_verify(&pubkey, data, &sig, &cp, false) {
        Ok(v) => v,
        Err(e) => panic!("verify ecdsa: {e}"),
    };
    assert_eq!(res, ValidityIndicator::Valid);
}
