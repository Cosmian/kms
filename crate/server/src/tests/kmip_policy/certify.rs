use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509NameBuilder, X509Req},
};

use super::helpers::{assert_policy_denied, params_with_default_policy};
use crate::core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_csr;

fn csr(key: &PKey<Private>, digest: MessageDigest) -> X509Req {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "dev.example").unwrap();
    let mut b = X509Req::builder().unwrap();
    b.set_version(0).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.sign(key, digest).unwrap();
    b.build()
}

fn rsa(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

fn ec(nid: Nid) -> PKey<Private> {
    PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap()).unwrap()
}

#[test]
fn csr_key_size_is_checked_under_default_policy() {
    let params = params_with_default_policy();
    let sha256 = MessageDigest::sha256();
    enforce_kmip_algorithm_policy_for_csr(&params, &csr(&rsa(3072), sha256)).unwrap();
    assert_policy_denied(enforce_kmip_algorithm_policy_for_csr(
        &params,
        &csr(&rsa(2048), sha256),
    ));
}

#[test]
fn csr_curve_is_checked_under_default_policy() {
    let params = params_with_default_policy();
    let sha256 = MessageDigest::sha256();
    enforce_kmip_algorithm_policy_for_csr(&params, &csr(&ec(Nid::X9_62_PRIME256V1), sha256))
        .unwrap();
    // secp224r1 is outside the DEFAULT curve allowlist in every build
    assert_policy_denied(enforce_kmip_algorithm_policy_for_csr(
        &params,
        &csr(&ec(Nid::SECP224R1), sha256),
    ));
}

// FIPS OpenSSL refuses to sign with SHA-1, so the request cannot be built there.
#[cfg(feature = "non-fips")]
#[test]
fn csr_sha1_signature_is_denied_under_default_policy() {
    assert_policy_denied(enforce_kmip_algorithm_policy_for_csr(
        &params_with_default_policy(),
        &csr(&rsa(3072), MessageDigest::sha1()),
    ));
}

#[cfg(feature = "non-fips")]
#[test]
fn csr_secp256k1_is_denied_under_default_policy() {
    assert_policy_denied(enforce_kmip_algorithm_policy_for_csr(
        &params_with_default_policy(),
        &csr(&ec(Nid::SECP256K1), MessageDigest::sha256()),
    ));
}

/// The SHA-3 RSA signature OID is identified (not "unknown") and refused by the allowlist,
/// which only names the SHA-2 RSA signatures.
#[test]
fn csr_sha3_rsa_signature_is_identified_and_refused_under_default_policy() {
    let err = enforce_kmip_algorithm_policy_for_csr(
        &params_with_default_policy(),
        &csr(&rsa(3072), MessageDigest::sha3_256()),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("SHA3256WithRSAEncryption"),
        "{err}"
    );
}

/// An ML-DSA-44 public key (right length, arbitrary bytes: `OpenSSL` only checks the length) is
/// identified by its SPKI algorithm and accepted by the DEFAULT allowlist.
#[cfg(feature = "non-fips")]
#[test]
fn ml_dsa_public_key_is_identified_by_spki_under_default_policy() {
    use openssl::pkey::Public;

    use crate::core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_public_key;

    // SEQUENCE { SEQUENCE { OID id-ml-dsa-44 }, BIT STRING (1312 bytes) }
    let mut der = vec![0x30, 0x82, 0x05, 0x32, 0x30, 0x0B];
    der.extend([
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    ]);
    der.extend([0x03, 0x82, 0x05, 0x21, 0x00]);
    der.extend(vec![0x42; 1312]);
    let key: PKey<Public> = PKey::public_key_from_der(&der).unwrap();
    enforce_kmip_algorithm_policy_for_public_key(
        &params_with_default_policy(),
        "Certify",
        &key,
        None,
    )
    .unwrap();
}
