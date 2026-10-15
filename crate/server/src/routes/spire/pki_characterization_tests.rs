//! Characterization of the SPIRE PKI helpers and `sign_intermediate` at BASE.

use std::{collections::HashSet, sync::Arc};

use actix_web::{App, test as actix_test, web::Data};
use cosmian_kms_interfaces::UserId;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
    kmip_attributes::Attributes,
    kmip_operations::{Certify, GetAttributes},
    kmip_types::{
        CertificateAttributes, CryptographicAlgorithm, LinkType, VendorAttribute,
        VendorAttributeValue,
    },
    requests::create_rsa_key_pair_request,
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    stack::Stack,
    x509::{X509, X509NameBuilder, X509ReqBuilder, extension::SubjectAlternativeName},
};
use serde_json::{Value, json};

use super::{parse_ttl_days, sign_intermediate};
use crate::{
    config::ServerParams, core::KMS, openssl_providers::init_openssl_providers_for_tests,
    result::KResult, tests::test_utils::https_clap_config,
};

#[test]
fn characterization_parse_ttl_days_table() {
    let cases: [(&str, Option<i32>); 24] = [
        ("", None),
        ("   ", None),
        ("h", None),
        ("s", None),
        ("d", None),
        ("0", Some(0)),
        ("0h", Some(0)),
        ("1s", Some(1)),
        ("86401s", Some(2)),
        ("24h", Some(1)),
        ("23h", Some(1)),
        ("48h", Some(2)),
        ("7d", Some(7)),
        (" 7d ", Some(7)),
        ("7 d", Some(7)),
        ("-1h", None),
        ("1.5h", None),
        ("1hh", None),
        ("1D", None),
        ("1m", None),
        ("2h3s", None),
        ("99999999999999d", None),
        ("172800", Some(2)),
        ("hd", None),
    ];
    for (input, expected) in cases {
        assert_eq!(parse_ttl_days(input), expected, "input {input:?}");
    }
}

const LABEL: &str = "vault_pki_ca";
const CA_EXT: &[u8] = b"[v3_ca]\nsubjectKeyIdentifier=hash\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,crlSign,digitalSignature\n";

fn csr_pem() -> String {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "intermediate").unwrap();
    let mut builder = X509ReqBuilder::new().unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder.set_pubkey(&key).unwrap();
    let mut extensions = Stack::new().unwrap();
    let ctx = builder.x509v3_context(None);
    extensions
        .push(
            SubjectAlternativeName::new()
                .uri("spiffe://example.org/x")
                .build(&ctx)
                .unwrap(),
        )
        .unwrap();
    builder.add_extensions(&extensions).unwrap();
    builder
        .sign(&key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
}

/// KMS with a tagged RSA CA key pair owned by the default user, and a self-signed CA certificate
/// linked to the public key.
async fn kms_without_key() -> KResult<Arc<KMS>> {
    init_openssl_providers_for_tests();
    let mut config = https_clap_config();
    config.vault.vault_pki_ca_key_label = LABEL.to_owned();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(config)?)).await?,
    ))
}

async fn kms_with_ca(with_certificate: bool) -> KResult<Arc<KMS>> {
    let kms = Box::pin(kms_without_key()).await?;
    let owner = UserId::from(kms.params.default_username.as_str());
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(
            "C=FR, O=KMS Test, CN=Root CA",
        )?),
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(CA_EXT.to_vec()),
        }]),
        ..Attributes::default()
    };
    if !with_certificate {
        // a tagged CA private key without any certificate
        let pair = kms
            .create_key_pair(
                create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, [LABEL], 2048, false, None)?,
                &owner,
            )
            .await?;
        assert!(!pair.private_key_unique_identifier.to_string().is_empty());
        return Ok(kms);
    }
    let cert_id = kms
        .certify(
            Certify {
                attributes: Some(attributes),
                ..Certify::default()
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();
    let sk_id = kms
        .get_attributes(GetAttributes::from(cert_id), &owner)
        .await?
        .attributes
        .get_link(LinkType::PrivateKeyLink)
        .unwrap()
        .to_string();
    let owm = kms.database.retrieve_object(&sk_id).await?.unwrap();
    kms.database
        .update_object(
            &sk_id,
            owm.object(),
            owm.attributes(),
            Some(&HashSet::from([LABEL.to_owned()])),
        )
        .await?;
    Ok(kms)
}

async fn call(kms: &Arc<KMS>, body: &Value) -> (u16, Value) {
    let app = actix_test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .service(sign_intermediate),
    )
    .await;
    let req = actix_test::TestRequest::put()
        .uri("/root/sign-intermediate")
        .set_payload(body.to_string())
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let bytes = actix_test::read_body(resp).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn characterization_sign_intermediate_signs_csr_with_ca() {
    let kms = Box::pin(kms_with_ca(true)).await.unwrap();
    let (status, body) = call(
        &kms,
        &json!({"csr": csr_pem(), "uri_sans": ["spiffe://example.org/x"], "ttl": "48h"}),
    )
    .await;
    assert_eq!(status, 200);
    let data = body.get("data").unwrap();
    let certificate = X509::from_pem(
        data.get("certificate")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let issuing_ca = data.get("issuing_ca").unwrap().as_str().unwrap();
    let ca = X509::from_pem(issuing_ca.as_bytes()).unwrap();
    let chain = data.get("ca_chain").unwrap().as_array().unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain.first().unwrap().as_str().unwrap(), issuing_ca);
    assert!(certificate.verify(&ca.public_key().unwrap()).unwrap());
    assert_eq!(
        certificate.issuer_name().to_der().unwrap(),
        ca.subject_name().to_der().unwrap()
    );
    let cn = certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap()
        .data()
        .to_string()
        .unwrap();
    assert_eq!(cn, "intermediate");
    let lifetime = certificate
        .not_before()
        .diff(certificate.not_after())
        .unwrap();
    assert_eq!(lifetime.days, 2);
    // CA:TRUE with pathlen 0 set by the server
    let der = certificate.to_der().unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
    let bc = parsed.basic_constraints().unwrap().unwrap();
    assert!(bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, Some(0));
}

#[tokio::test]
async fn characterization_sign_intermediate_rejects_empty_uri_sans() {
    let kms = Box::pin(kms_with_ca(true)).await.unwrap();
    let (status, body) = call(&kms, &json!({"csr": csr_pem()})).await;
    assert_eq!(status, 400);
    assert_eq!(
        body.to_string(),
        r#"{"errors":["uri_sans must not be empty — a SPIFFE ID URI SAN is required"]}"#
    );
}

#[tokio::test]
async fn characterization_sign_intermediate_rejects_invalid_body() {
    let kms = Box::pin(kms_with_ca(true)).await.unwrap();
    let (status, body) = call(&kms, &json!({"uri_sans": ["a"]})).await;
    assert_eq!(status, 400);
    assert_eq!(
        body.to_string(),
        r#"{"errors":["invalid sign-intermediate body: missing field `csr` at line 1 column 18"]}"#
    );
}

#[tokio::test]
async fn characterization_sign_intermediate_without_ca_key() {
    let kms = Box::pin(kms_without_key()).await.unwrap();
    let (status, body) = call(&kms, &json!({"csr": csr_pem(), "uri_sans": "a"})).await;
    assert_eq!(status, 500);
    assert_eq!(
        body.to_string(),
        r#"{"errors":["PKI CA private key with tag 'vault_pki_ca' not found in KMS. Create a key pair and tag it with 'vault_pki_ca' first."]}"#
    );
}

#[tokio::test]
async fn characterization_sign_intermediate_without_ca_certificate() {
    let kms = Box::pin(kms_with_ca(false)).await.unwrap();
    let (status, body) = call(&kms, &json!({"csr": csr_pem(), "uri_sans": "a"})).await;
    assert_eq!(status, 500);
    assert_eq!(
        body.to_string(),
        r#"{"errors":["Invalid Request: No CertificateLink found in the public key"]}"#
    );
}
