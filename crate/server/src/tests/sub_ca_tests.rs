//! Sub-CA flow: a CSR is generated for a key that stays in the KMS, signed by a root CA
//! (as an offline root would do), and the resulting certificate is tagged by serial.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashSet, sync::Arc};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{
            CertificateType, CryptographicUsageMask, ErrorReason, RevocationReason,
            RevocationReasonCode,
        },
        kmip_2_1::{
            extra::{
                VENDOR_ATTR_X509_EXTENSION,
                tagging::{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX, VENDOR_ID_COSMIAN},
            },
            kmip_attributes::{Attribute, Attributes},
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_operations::{Certify, Get, GetAttributes, Import, ModifyAttribute, Revoke},
            kmip_types::{
                CertificateRequestType, CryptographicAlgorithm, Link, LinkType,
                LinkedObjectIdentifier, UniqueIdentifier, VendorAttribute, VendorAttributeValue,
            },
            requests::create_rsa_key_pair_request,
        },
    },
    cosmian_kms_crypto::openssl::kmip_public_key_to_openssl,
};
use openssl::x509::{X509, X509Req};

use crate::{
    config::ServerParams,
    core::{
        KMS,
        operations::{generate_crl::get_cached_crl, generate_csr::generate_csr},
    },
    error::KmsError,
    middlewares::UserId,
    openssl_providers::init_openssl_providers_for_tests,
    result::KResult,
    tests::test_utils::{https_clap_config, https_clap_config_opts},
};

const CA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,crlSign
";

const EMPTY_TAGS: [&str; 0] = [];

async fn make_kms() -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
    ))
}

fn user(name: &str) -> UserId {
    UserId::try_new(name).expect("valid test user")
}

fn extension_attribute() -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(CA_EXT.to_vec()),
    }
}

/// Self-signed root CA; returns `(certificate id, private key id)`.
async fn make_root(kms: &KMS, owner: &UserId) -> KResult<(String, String)> {
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        certificate_attributes: Some(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CertificateAttributes::parse_subject_line(
                "C=FR, O=KMS Test, CN=Offline Root",
            )?,
        ),
        vendor_attributes: Some(vec![extension_attribute()]),
        ..Attributes::default()
    };
    let cert_id = kms
        .certify(
            Certify {
                attributes: Some(attributes),
                ..Certify::default()
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string();
    let attributes = kms
        .get_attributes(GetAttributes::from(cert_id.clone()), owner)
        .await?
        .attributes;
    let sk_id = attributes
        .get_link(LinkType::PrivateKeyLink)
        .expect("root certificate has a PrivateKeyLink")
        .to_string();
    Ok((cert_id, sk_id))
}

/// A non-sensitive RSA key pair in the database; returns `(private key id, public key id)`.
async fn make_key_pair(kms: &KMS, owner: &UserId) -> KResult<(String, String)> {
    let response = kms
        .create_key_pair(
            create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?,
            owner,
        )
        .await?;
    Ok((
        response.private_key_unique_identifier.to_string(),
        response.public_key_unique_identifier.to_string(),
    ))
}

async fn certificate(kms: &KMS, owner: &UserId, id: &str) -> KResult<X509> {
    let response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
                ..Get::default()
            },
            owner,
        )
        .await?;
    let Object::Certificate(certificate) = response.object else {
        panic!("not a certificate");
    };
    Ok(X509::from_der(&certificate.certificate_value)?)
}

#[tokio::test]
async fn sub_ca_csr_is_signed_by_root_and_certificate_is_tagged_by_serial() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let (root_id, root_sk_id) = make_root(&kms, &owner).await?;
    let (sub_sk_id, sub_pk_id) = make_key_pair(&kms, &owner).await?;

    let csr = generate_csr(
        &kms,
        &sub_sk_id,
        "C=FR, O=KMS Test, CN=Delegated Sub CA",
        &owner,
    )
    .await?;
    let sub_public_key = csr.public_key()?;
    assert!(
        csr.verify(&sub_public_key)?,
        "CSR must be self-signed by the key"
    );
    assert_eq!(
        csr.subject_name()
            .entries()
            .map(|e| String::from_utf8(e.data().as_slice().to_vec()).unwrap())
            .collect::<Vec<_>>(),
        ["FR", "KMS Test", "Delegated Sub CA"]
    );

    // The (offline) root signs the CSR, with the sub-CA extensions.
    let mut issuer_links = Attributes {
        vendor_attributes: Some(vec![extension_attribute()]),
        ..Attributes::default()
    };
    issuer_links.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(root_id.clone()),
    );
    issuer_links.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(root_sk_id),
    );
    let sub_id = kms
        .certify(
            Certify {
                certificate_request_type: Some(CertificateRequestType::PKCS10),
                certificate_request_value: Some(csr.to_der()?),
                attributes: Some(issuer_links),
                ..Certify::default()
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();

    let root = certificate(&kms, &owner, &root_id).await?;
    let sub = certificate(&kms, &owner, &sub_id).await?;
    assert!(
        sub.verify(root.public_key()?.as_ref())?,
        "sub-CA is signed by the root"
    );
    assert_eq!(sub.issuer_name().to_der()?, root.subject_name().to_der()?);
    assert!(
        sub.public_key()?.public_eq(&sub_public_key),
        "the certificate certifies the CSR key, which never left the KMS"
    );
    // The public key of the KMS-held pair is the one in the certificate
    let pk = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(sub_pk_id)),
                ..Get::default()
            },
            &owner,
        )
        .await?;
    assert!(
        kmip_public_key_to_openssl(&pk.object)?.public_eq(&sub_public_key),
        "the CSR key is the public key of the stored KMS key pair"
    );

    // Serial tag: `_serial=<UPPERCASE HEX>`
    let tags: HashSet<String> = kms.database.retrieve_tags(&sub_id).await?;
    let serial = sub.serial_number().to_bn()?.to_hex_str()?.to_string();
    assert!(
        tags.contains(&format!("{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX}{serial}")),
        "missing serial tag, got {tags:?}"
    );
    Ok(())
}

#[tokio::test]
async fn csr_generation_is_denied_without_sign_permission() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let (sk_id, _) = make_key_pair(&kms, &owner).await?;
    let result = generate_csr(&kms, &sk_id, "CN=x", &user("intruder@example.com")).await;
    assert!(
        matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _))
        ),
        "a user without Sign on the key must not obtain a CSR, got {:?}",
        result.map(|_csr| ())
    );
    Ok(())
}

#[tokio::test]
async fn csr_generation_rejects_bad_input() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let (sk_id, pk_id) = make_key_pair(&kms, &owner).await?;
    for subject in ["", "   ", "no-equals-sign", "CN="] {
        let result = generate_csr(&kms, &sk_id, subject, &owner).await;
        assert!(
            matches!(result, Err(KmsError::InvalidRequest(_))),
            "subject '{subject}' must be rejected as InvalidRequest, got {:?}",
            result.map(|_csr| ())
        );
    }
    let result = generate_csr(&kms, &pk_id, "CN=x", &owner).await;
    assert!(
        matches!(result, Err(KmsError::InvalidRequest(_))),
        "a public key cannot sign a CSR, got {:?}",
        result.map(|_csr| ())
    );
    let result = generate_csr(&kms, "does-not-exist", "CN=x", &owner).await;
    assert!(
        matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _))
        ),
        "unknown key, got {:?}",
        result.map(|_csr| ())
    );
    // a CSR generated for a valid input still parses back
    let csr = generate_csr(&kms, &sk_id, "CN=ok", &owner).await?;
    X509Req::from_pem(&csr.to_pem()?)?;
    Ok(())
}

#[tokio::test]
async fn user_granted_only_sign_on_the_private_key_gets_a_csr() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let operator = user("operator@example.com");
    let (sk_id, _) = make_key_pair(&kms, &owner).await?;
    kms.database
        .grant_operations(&sk_id, &operator, HashSet::from([KmipOperation::Sign]))
        .await?;
    let csr = generate_csr(&kms, &sk_id, "CN=operator request", &operator).await?;
    assert!(csr.verify(csr.public_key()?.as_ref())?);
    Ok(())
}

/// KMIP §4.57: a revoked (Deactivated) key no longer signs, so no CSR is produced with it.
#[tokio::test]
async fn csr_generation_refuses_a_deactivated_key() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let (sk_id, _) = make_key_pair(&kms, &owner).await?;
    revoke_certificate(&kms, &owner, &sk_id).await?;
    let Err(err) = generate_csr(&kms, &sk_id, "CN=x", &owner).await else {
        panic!("a Deactivated key must not sign a CSR");
    };
    assert!(
        err.to_string().contains("only Active keys may sign"),
        "{err}"
    );
    Ok(())
}

/// The `PublicKeyLink` of a private key is user-controlled: it must neither be followed (it could
/// point to an object the caller has no grant on) nor make the CSR fail with a dump of that object.
#[tokio::test]
async fn csr_generation_ignores_the_public_key_link_of_the_private_key() -> KResult<()> {
    let kms = make_kms().await?;
    let alice = user("alice@example.com");
    let bob = user("bob@example.com");
    let (alice_sk, _) = make_key_pair(&kms, &alice).await?;
    let (bob_sk, _) = make_key_pair(&kms, &bob).await?;
    kms.modify_attribute(
        ModifyAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(alice_sk.clone())),
            new_attribute: Attribute::Link(Link {
                link_type: LinkType::PublicKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(bob_sk),
            }),
        },
        &alice,
    )
    .await?;
    let csr = generate_csr(&kms, &alice_sk, "CN=alice", &alice).await?;
    assert!(csr.verify(csr.public_key()?.as_ref())?);
    Ok(())
}

/// A key whose usage mask lacks Sign does not sign a CSR, as for the KMIP Sign operation.
#[tokio::test]
async fn csr_generation_refuses_a_key_that_cannot_sign() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let (sk_id, _) = make_key_pair(&kms, &owner).await?;
    kms.modify_attribute(
        ModifyAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(sk_id.clone())),
            new_attribute: Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
        },
        &owner,
    )
    .await?;
    let Err(err) = generate_csr(&kms, &sk_id, "CN=x", &owner).await else {
        panic!("a key without the Sign usage must not sign a CSR");
    };
    assert!(err.to_string().contains("does not allow Sign"), "{err}");
    Ok(())
}

/// Ed25519 keys sign without a digest, unlike RSA and EC.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn csr_for_a_database_ed25519_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_types::RecommendedCurve, requests::create_ec_key_pair_request,
    };
    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let response = kms
        .create_key_pair(
            create_ec_key_pair_request(
                VENDOR_ID_COSMIAN,
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVEED25519,
                false,
                None,
            )?,
            &owner,
        )
        .await?;
    let csr = generate_csr(
        &kms,
        &response.private_key_unique_identifier.to_string(),
        "CN=ed25519",
        &owner,
    )
    .await?;
    assert!(csr.verify(csr.public_key()?.as_ref())?);
    Ok(())
}

/// A key-agreement key cannot sign: the caller made a bad request, the server did not fail.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn csr_generation_refuses_an_x25519_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_types::RecommendedCurve, requests::create_ec_key_pair_request,
    };

    let kms = make_kms().await?;
    let owner = user("pki-admin@example.com");
    let response = kms
        .create_key_pair(
            create_ec_key_pair_request(
                VENDOR_ID_COSMIAN,
                None,
                EMPTY_TAGS,
                RecommendedCurve::CURVE25519,
                false,
                None,
            )?,
            &owner,
        )
        .await?;
    let sk_id = response.private_key_unique_identifier.to_string();
    let result = generate_csr(&kms, &sk_id, "CN=x25519", &owner).await;
    assert!(
        matches!(result, Err(KmsError::InvalidRequest(_))),
        "expected InvalidRequest, got {:?}",
        result.map(|_csr| ())
    );
    Ok(())
}

/// Issue a leaf certificate under `(root_id, root_sk_id)`; returns its id.
async fn make_leaf(kms: &KMS, owner: &UserId, root_id: &str, root_sk_id: &str) -> KResult<String> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        certificate_attributes: Some(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CertificateAttributes::parse_subject_line(
                "C=FR, O=KMS Test, CN=Leaf",
            )?,
        ),
        ..Attributes::default()
    };
    attributes.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(root_id.to_owned()),
    );
    attributes.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(root_sk_id.to_owned()),
    );
    Ok(kms
        .certify(
            Certify {
                attributes: Some(attributes),
                ..Certify::default()
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string())
}

async fn revoke_certificate(kms: &KMS, owner: &UserId, id: &str) -> KResult<()> {
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Unspecified,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        owner,
    )
    .await?;
    Ok(())
}

/// Import a copy of certificate `der` owned by `owner`, with the given links.
async fn import_certificate_copy(
    kms: &KMS,
    owner: &UserId,
    der: &[u8],
    links: &[(LinkType, &str)],
) -> KResult<String> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };
    for (link_type, id) in links {
        attributes.set_link(
            *link_type,
            LinkedObjectIdentifier::TextString((*id).to_owned()),
        );
    }
    Ok(kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(String::new()),
                object_type: ObjectType::Certificate,
                replace_existing: None,
                key_wrap_type: None,
                attributes,
                object: Object::Certificate(Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: der.to_vec(),
                }),
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string())
}

/// Server-triggered CRL regeneration authorizes the CA key as the issuer certificate's owner:
/// a user who imports a copy of someone else's CA certificate, linked to that CA's private key,
/// must not be able to make the server sign a CRL with that key by revoking a certificate.
#[tokio::test]
async fn server_crl_regeneration_does_not_sign_with_a_key_its_certificate_owner_cannot_use()
-> KResult<()> {
    init_openssl_providers_for_tests();
    let kms = Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config_opts(
            Some("https://kms.example.com".to_owned()),
        ))?))
        .await?,
    );
    let alice = user("alice@example.com");
    let mallory = user("mallory@example.com");
    let (root_id, root_sk_id) = make_root(&kms, &alice).await?;

    // Control: the CA owner revoking a leaf makes the server publish a CRL for the CA.
    let leaf_id = make_leaf(&kms, &alice, &root_id, &root_sk_id).await?;
    revoke_certificate(&kms, &alice, &leaf_id).await?;
    assert!(
        get_cached_crl(&root_id, &kms).await.is_some(),
        "automatic CRL regeneration must work for the CA owner"
    );

    // Attack: mallory copies the CA certificate (linked to alice's key) and a leaf, then
    // revokes his copy of the leaf.
    let victim_leaf_id = make_leaf(&kms, &alice, &root_id, &root_sk_id).await?;
    let root_der = certificate(&kms, &alice, &root_id).await?.to_der()?;
    let leaf_der = certificate(&kms, &alice, &victim_leaf_id).await?.to_der()?;
    let root_copy_id = import_certificate_copy(
        &kms,
        &mallory,
        &root_der,
        &[(LinkType::PrivateKeyLink, &root_sk_id)],
    )
    .await?;
    let leaf_copy_id = import_certificate_copy(
        &kms,
        &mallory,
        &leaf_der,
        &[(LinkType::CertificateLink, &root_copy_id)],
    )
    .await?;
    revoke_certificate(&kms, &mallory, &leaf_copy_id).await?;
    assert!(
        get_cached_crl(&root_copy_id, &kms).await.is_none(),
        "the server must not sign a CRL with a CA key its certificate's owner cannot use"
    );
    Ok(())
}
