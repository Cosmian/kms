//! EST (RFC 7030) and SCEP (RFC 8894) enrollment endpoint tests.
//!
//! The endpoints are exercised through an in-process actix application backed by a real
//! `KMS` instance (temporary `SQLite` database) and a CA created with KMIP `Certify`. The SCEP
//! client side (signed `pkiMessage`, `pkcsPKIEnvelope`) is built with the same CMS helpers
//! the server uses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashSet, sync::Arc};

use actix_web::{
    App,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test,
    web::Data,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cosmian_kms_access::access::Access;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            extra::{
                VENDOR_ATTR_X509_EXTENSION,
                tagging::{SYSTEM_TAG_CERTIFICATE, VENDOR_ID_COSMIAN},
            },
            kmip_attributes::Attributes,
            kmip_operations::{Certify, Revoke},
            kmip_types::{
                CertificateAttributes, CryptographicAlgorithm, UniqueIdentifier, VendorAttribute,
                VendorAttributeValue,
            },
        },
    },
    cosmian_kms_crypto::openssl::{
        csr_attrs::{csr_challenge_password, csr_with_challenge_password},
        scep_cms::{
            FAIL_INFO_BAD_CERT_ID, FAIL_INFO_BAD_REQUEST, MESSAGE_TYPE_CERT_REP,
            MESSAGE_TYPE_PKCS_REQ, MESSAGE_TYPE_RENEWAL_REQ, NONCE_LEN, PKI_STATUS_FAILURE,
            PKI_STATUS_SUCCESS, ScepAttrs, build_signed_pkimessage, decrypt_envelope,
            envelope_for_recipient, parse_signed_pkimessage,
        },
    },
    cosmian_kms_interfaces::ObjectHandle,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkcs7::Pkcs7,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509, X509NameBuilder, X509Req},
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    config::{EstConfig, ScepConfig, ServerParams, TlsConfig},
    core::{
        KMS, certificate::retrieve_issuer_private_key_and_certificate,
        operations::certify::template::CertTemplate,
    },
    middlewares::{UserId, user_from_client_certificate},
    openssl_providers::init_openssl_providers_for_tests,
    result::KResult,
    routes::{enrollment::ENROLLMENT_SERVICE_USER, est, scep},
    tests::test_utils::{https_clap_config, test_kms_with_config},
};

const CA_UID: &str = "enrollment-test-ca";
const CHALLENGE: &str = "SecretChallenge123";
const CA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment
";

// ── Fixture ──────────────────────────────────────────────────────────────────

fn config(est_enabled: bool, scep_enabled: bool, allow_renewal: bool) -> crate::config::ClapConfig {
    let mut c = https_clap_config();
    // The in-process app does not terminate TLS; only the startup checks read these (EST needs
    // TLS, and mutual TLS a client CA).
    c.tls.tls_cert_file =
        Some("../../test_data/certificates/client_server/server/kmserver.acme.com.crt".into());
    c.tls.tls_key_file =
        Some("../../test_data/certificates/client_server/server/kmserver.acme.com.key".into());
    c.tls.clients_ca_cert_file =
        Some("../../test_data/certificates/client_server/ca/ca.crt".into());
    c.est = EstConfig {
        est_enabled,
        est_ca_uid: Some(CA_UID.to_owned()),
        est_require_client_cert: false,
        est_bootstrap_username: Some("testuser".to_owned()),
        est_bootstrap_password: Some("testpass".to_owned()),
        est_template: Some("iot_device".to_owned()),
    };
    c.scep = ScepConfig {
        scep_enabled,
        scep_ca_uid: Some(CA_UID.to_owned()),
        scep_challenge_password: Some(CHALLENGE.to_owned()),
        scep_allow_renewal_without_challenge: allow_renewal,
        scep_template: Some("iot_device".to_owned()),
    };
    c.templates.insert(
        "iot_device".to_owned(),
        CertTemplate {
            name: "iot_device".to_owned(),
            allowed_ekus: vec!["clientAuth".to_owned()],
            subject_cn_regex: Some(r"[a-z0-9-]+\.iot\.example".to_owned()),
            max_validity_days: 365,
            default_validity_days: 90,
            ..CertTemplate::default()
        },
    );
    c
}

/// Start a KMS with the enrollment endpoints configured, create the CA (owned by
/// `default_username`) and delegate it to the enrollment service identity.
async fn make_kms(
    est_enabled: bool,
    scep_enabled: bool,
    allow_renewal: bool,
) -> KResult<(Arc<KMS>, X509)> {
    make_kms_with(est_enabled, scep_enabled, allow_renewal, |_| {}).await
}

/// Like [`make_kms`], letting the caller adjust the configuration first.
async fn make_kms_with(
    est_enabled: bool,
    scep_enabled: bool,
    allow_renewal: bool,
    tweak: impl FnOnce(&mut crate::config::ClapConfig),
) -> KResult<(Arc<KMS>, X509)> {
    // boxed: the KMS bring-up future is large
    Box::pin(make_kms_inner(
        est_enabled,
        scep_enabled,
        allow_renewal,
        tweak,
        None,
    ))
    .await
}

/// SCEP-enabled KMS whose CA is created and delegated by `ca_owner` (not `default_username`).
async fn make_scep_kms_with_ca_owner(ca_owner: &str) -> KResult<(Arc<KMS>, X509)> {
    Box::pin(make_kms_inner(false, true, true, |_| {}, Some(ca_owner))).await
}

async fn make_kms_inner(
    est_enabled: bool,
    scep_enabled: bool,
    allow_renewal: bool,
    tweak: impl FnOnce(&mut crate::config::ClapConfig),
    ca_owner: Option<&str>,
) -> KResult<(Arc<KMS>, X509)> {
    cosmian_logger::log_init(None);
    let mut conf = config(est_enabled, scep_enabled, allow_renewal);
    tweak(&mut conf);
    let kms = test_kms_with_config(conf).await?;
    let owner = UserId::from(ca_owner.unwrap_or(kms.params.default_username.as_str()));

    let attrs = Attributes {
        unique_identifier: Some(UniqueIdentifier::TextString(CA_UID.to_owned())),
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(3072),
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(
            "C=FR, O=KMS Test, CN=Enrollment Test CA",
        )?),
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(CA_EXT.to_vec()),
        }]),
        ..Attributes::default()
    };
    kms.certify(
        Certify {
            attributes: Some(attrs),
            ..Certify::default()
        },
        &owner,
    )
    .await?;
    // Delegate the CA to enrollment: `certify` on the CA certificate and its private key.
    let (ca_key, _) = Box::pin(retrieve_issuer_private_key_and_certificate(
        None,
        Some(ObjectHandle::from(CA_UID)),
        &kms,
        &owner,
    ))
    .await?;
    for uid in [CA_UID.to_owned(), ca_key.id().to_owned()] {
        kms.grant_access(&certify_grant(uid), &owner).await?;
    }
    let ca_cert = crate::routes::enrollment::load_ca_chain(&kms, CA_UID)
        .await?
        .remove(0);
    Ok((kms, ca_cert))
}

/// The `certify` grant delegating object `uid` to the enrollment service identity.
fn certify_grant(uid: String) -> Access {
    Access {
        unique_identifier: Some(UniqueIdentifier::TextString(uid)),
        user_id: ENROLLMENT_SERVICE_USER.to_owned(),
        operation_types: vec![KmipOperation::Certify],
    }
}

/// Revoke the enrollment delegation on the CA private key.
async fn undelegate_ca_key(kms: &KMS) -> KResult<()> {
    let owner: UserId = kms.params.default_username.clone().into();
    let (ca_key, _) = Box::pin(retrieve_issuer_private_key_and_certificate(
        None,
        Some(ObjectHandle::from(CA_UID)),
        kms,
        &owner,
    ))
    .await?;
    kms.revoke_access(&certify_grant(ca_key.id().to_owned()), &owner)
        .await
}

macro_rules! app {
    ($kms:expr) => {
        test::init_service(
            App::new()
                .app_data(Data::new($kms.clone()))
                .service(est::get_cacerts)
                .service(est::get_csrattrs)
                .service(est::post_simpleenroll)
                .service(est::post_simplereenroll)
                .service(scep::scep_get)
                .service(scep::scep_post),
        )
        .await
    };
}

fn rsa_key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

fn csr(key: &PKey<Private>, cn: &str) -> X509Req {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let mut b = X509Req::builder().unwrap();
    b.set_version(0).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}

fn self_signed(key: &PKey<Private>, cn: &str) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}

fn basic_auth(user: &str, password: &str) -> (&'static str, String) {
    (
        "Authorization",
        format!("Basic {}", STANDARD.encode(format!("{user}:{password}"))),
    )
}

/// Certificates carried by a certs-only CMS (`SignedData`).
fn certs_of(der: &[u8]) -> Vec<X509> {
    let p7 = Pkcs7::from_der(der).unwrap();
    p7.signed()
        .unwrap()
        .certificates()
        .unwrap()
        .iter()
        .map(ToOwned::to_owned)
        .collect()
}

fn h<'a>(headers: &'a actix_web::http::header::HeaderMap, name: &str) -> &'a str {
    headers.get(name).unwrap().to_str().unwrap()
}

fn assert_issued_by(cert: &X509, ca: &X509) {
    assert!(cert.verify(&ca.public_key().unwrap()).unwrap());
    assert_eq!(
        cert.issuer_name().to_der().unwrap(),
        ca.subject_name().to_der().unwrap()
    );
}

async fn body_of<B: actix_web::body::MessageBody>(
    resp: ServiceResponse<B>,
) -> (StatusCode, Vec<u8>, actix_web::http::header::HeaderMap) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = test::read_body(resp).await.to_vec();
    (status, body, headers)
}

// ── EST ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_endpoints_return_404() -> KResult<()> {
    let (kms, _) = make_kms(false, false, true).await?;
    let app = app!(kms);
    for uri in [
        "/.well-known/est/cacerts",
        "/.well-known/est/csrattrs",
        "/scep?operation=GetCACaps",
        "/scep?operation=GetCACert",
        "/scep?operation=PKIOperation&message=AAAA",
    ] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    for uri in [
        "/.well-known/est/simpleenroll",
        "/.well-known/est/simplereenroll",
        "/scep?operation=PKIOperation",
    ] {
        let resp = test::call_service(&app, test::TestRequest::post().uri(uri).to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn est_cacerts_returns_base64_certs_only_chain() -> KResult<()> {
    let (kms, ca) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/est/cacerts")
            .to_request(),
    )
    .await;
    let (status, body, headers) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h(&headers, "content-type"), "application/pkcs7-mime");
    assert_eq!(h(&headers, "content-transfer-encoding"), "base64");
    let certs = certs_of(&STANDARD.decode(&body).unwrap());
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].to_der().unwrap(), ca.to_der().unwrap());
    Ok(())
}

#[tokio::test]
async fn est_csrattrs_advertises_extension_request() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/.well-known/est/csrattrs")
            .to_request(),
    )
    .await;
    let (status, body, headers) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h(&headers, "content-type"), "application/csrattrs");
    let der = STANDARD.decode(&body).unwrap();
    // SEQUENCE { OID 1.2.840.113549.1.9.14 (extensionRequest) }
    assert_eq!(der[0], 0x30);
    assert!(
        der.windows(9)
            .any(|w| w == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E])
    );
    Ok(())
}

async fn est_enroll<S, B>(
    app: &S,
    csr: &X509Req,
    auth: Option<(&str, String)>,
) -> (StatusCode, Vec<u8>, actix_web::http::header::HeaderMap)
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let mut req = test::TestRequest::post()
        .uri("/.well-known/est/simpleenroll")
        .insert_header(("Content-Type", "application/pkcs10"))
        .set_payload(STANDARD.encode(csr.to_der().unwrap()));
    if let Some(h) = auth {
        req = req.insert_header(h);
    }
    body_of(test::call_service(app, req.to_request()).await).await
}

#[tokio::test]
async fn est_simpleenroll_issues_certificate_under_template() -> KResult<()> {
    let (kms, ca) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let (status, body, headers) = est_enroll(
        &app,
        &csr(&key, "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        h(&headers, "content-type"),
        "application/pkcs7-mime; smime-type=certs-only"
    );
    let certs = certs_of(&STANDARD.decode(&body).unwrap());
    assert_eq!(certs.len(), 1, "only the issued certificate is returned");
    let cert = &certs[0];
    assert_issued_by(cert, &ca);
    assert!(cert.public_key().unwrap().public_eq(&key));
    // template-injected EKU and clamped validity
    let der = cert.to_der().unwrap();
    let (_, parsed) = X509Certificate::from_der(&der).unwrap();
    let eku = parsed.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    let validity = parsed.validity();
    let days = (validity.not_after.timestamp() - validity.not_before.timestamp()) / 86_400;
    assert_eq!(days, 90, "template default_validity_days");
    Ok(())
}

/// A device picks its own CN: an enrolled certificate must never authenticate as the KMS user
/// of that name, even when the TLS layer trusts the enrollment CA.
#[tokio::test]
async fn enrolled_certificates_never_authenticate_as_kms_users() -> KResult<()> {
    let (kms, _ca) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let device_key = rsa_key(2048);
    let (status, body, _) = est_enroll(
        &app,
        &csr(&device_key, "admin.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let enrolled = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    let err = user_from_client_certificate(&enrolled, Some(&[]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("EST/SCEP"), "{err}");

    // a certificate that was not enrolled still maps to its CN
    let plain = self_signed(&rsa_key(2048), "alice");
    assert_eq!(
        user_from_client_certificate(&plain, Some(&[]))?.into_string(),
        "alice"
    );
    // without a chain the issuers cannot be checked: refuse rather than assume there are none
    user_from_client_certificate(&plain, None).unwrap_err();

    // ... unless something in its verified chain was enrolled: the device holds the key of its
    // certificate and can sign an unmarked "alice" itself.
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "alice").unwrap();
    let name = name.build();
    let alice_key = rsa_key(2048);
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(8).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(enrolled.subject_name()).unwrap();
    b.set_pubkey(&alice_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(&device_key, MessageDigest::sha256()).unwrap();
    let forged = b.build();
    assert_eq!(
        user_from_client_certificate(&forged, Some(&[]))?.into_string(),
        "alice"
    );
    let err = user_from_client_certificate(&forged, Some(&[enrolled]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("EST/SCEP"), "{err}");
    Ok(())
}

#[tokio::test]
async fn est_simpleenroll_rejects_missing_or_wrong_credentials() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let csr = csr(&rsa_key(2048), "dev1.iot.example");
    let (status, _, headers) = est_enroll(&app, &csr, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(h(&headers, "www-authenticate").starts_with("Basic"));
    for auth in [
        basic_auth("testuser", "wrong"),
        basic_auth("other", "testpass"),
    ] {
        let (status, _, _) = est_enroll(&app, &csr, Some(auth)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

/// FIPS OpenSSL refuses to sign with a 1024-bit RSA key, so a weak-key CSR cannot be built there.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn est_simpleenroll_rejects_weak_rsa_key() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let (status, body, _) = est_enroll(
        &app,
        &csr(&rsa_key(1024), "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body).contains("below the template minimum"));
    Ok(())
}

#[tokio::test]
async fn est_simpleenroll_enforces_template() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    // CN outside the allowed pattern
    let (status, body, headers) = est_enroll(
        &app,
        &csr(&rsa_key(2048), "evil.example.com"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body).contains("does not match"));
    // The reason can quote the CSR: never let a browser render it as HTML (S100).
    assert_eq!(h(&headers, "content-type"), "text/plain; charset=utf-8");
    assert_eq!(h(&headers, "x-content-type-options"), "nosniff");
    Ok(())
}

/// The `iot_device` template constrains only the CN: a CSR whose CN matches but which also
/// asks for a DNS SAN must be refused (SANs are default-deny), without echoing the SAN.
#[tokio::test]
async fn est_simpleenroll_refuses_san_not_allowed_by_template() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "dev1.iot.example").unwrap();
    let mut b = X509Req::builder().unwrap();
    b.set_version(0).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    let san = openssl::x509::extension::SubjectAlternativeName::new()
        .dns("victim.bank.example")
        .build(&b.x509v3_context(None))
        .unwrap();
    let mut exts = openssl::stack::Stack::new().unwrap();
    exts.push(san).unwrap();
    b.add_extensions(&exts).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let (status, body, _) =
        est_enroll(&app, &b.build(), Some(basic_auth("testuser", "testpass"))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("DNS SAN is not allowed"), "{body}");
    assert!(!body.contains("victim"), "{body}");
    Ok(())
}

#[tokio::test]
async fn est_simplereenroll_requires_matching_identity_and_ca_issued_certificate() -> KResult<()> {
    let (kms, ca) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let (_, body, _) = est_enroll(
        &app,
        &csr(&key, "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    let current = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    let renew = |c: &X509Req| STANDARD.encode(c.to_der().unwrap()).into_bytes();

    // no TLS client certificate -> 401
    let resp = est::simple_reenroll(&kms, None, &renew(&csr(&key, "dev1.iot.example"))).await?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // same Subject, fresh key (rekey) -> 200 with a new certificate
    let new_key = rsa_key(2048);
    let resp = est::simple_reenroll(
        &kms,
        Some(&current),
        &renew(&csr(&new_key, "dev1.iot.example")),
    )
    .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let (_, body, _) = body_of(ServiceResponse::new(
        test::TestRequest::default().to_http_request(),
        resp,
    ))
    .await;
    let renewed = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    assert_issued_by(&renewed, &ca);
    assert!(renewed.public_key().unwrap().public_eq(&new_key));
    assert_ne!(
        renewed.serial_number().to_bn().unwrap(),
        current.serial_number().to_bn().unwrap()
    );

    // different Subject -> 400
    let resp =
        est::simple_reenroll(&kms, Some(&current), &renew(&csr(&key, "dev2.iot.example"))).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // certificate not issued by the EST CA -> 403
    let foreign = self_signed(&key, "dev1.iot.example");
    let resp =
        est::simple_reenroll(&kms, Some(&foreign), &renew(&csr(&key, "dev1.iot.example"))).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn est_simpleenroll_rejects_revoked_ca_issued_client_certificate() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let (_, body, _) = est_enroll(
        &app,
        &csr(&key, "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    let current = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    let same = csr(&rsa_key(2048), "dev1.iot.example");

    let resp = est::enroll_for_peer(&kms, Some(&current), &same).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let serial_hex = current
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();
    let (uid, _, _) = Box::pin(kms.database.find_certificate_by_serial(
        CA_UID,
        &serial_hex,
        kms.vendor_id(),
    ))
    .await?
    .expect("issued certificate is tracked");
    let owner: UserId = kms.params.default_username.clone().into();
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid)),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        &owner,
    )
    .await?;
    let resp = est::enroll_for_peer(&kms, Some(&current), &same).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// The serial tag only locates candidates: another object carrying a revoked device's tag must
/// not bring that device back (the stored certificate has to be the presented one).
#[tokio::test]
async fn serial_tag_planted_on_another_object_does_not_revive_a_revoked_certificate() -> KResult<()>
{
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let mut enrolled = Vec::new();
    for cn in ["dev1.iot.example", "dev2.iot.example"] {
        let (_, body, _) = est_enroll(
            &app,
            &csr(&rsa_key(2048), cn),
            Some(basic_auth("testuser", "testpass")),
        )
        .await;
        enrolled.push(certs_of(&STANDARD.decode(&body).unwrap()).remove(0));
    }
    let tag_of = |cert: &X509| {
        let serial_hex = cert
            .serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_string();
        crate::routes::enrollment::serial_tag(CA_UID, &serial_hex)
    };
    let uid_of = |tag: String| {
        let kms = kms.clone();
        async move {
            kms.database
                .list_uids_for_tags(&HashSet::from([tag]))
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        }
    };
    let revoked_uid = uid_of(tag_of(&enrolled[0])).await;
    let other_uid = uid_of(tag_of(&enrolled[1])).await;

    // plant the first certificate's tag on the second, Active, object
    let other = kms.database.retrieve_object(&other_uid).await?.unwrap();
    let mut tags = kms.database.retrieve_tags(&other_uid).await?;
    tags.insert(tag_of(&enrolled[0]));
    kms.database
        .update_object(&other_uid, other.object(), other.attributes(), Some(&tags))
        .await?;

    let owner: UserId = kms.params.default_username.clone().into();
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(revoked_uid)),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        &owner,
    )
    .await?;
    let resp = est::enroll_for_peer(
        &kms,
        Some(&enrolled[0]),
        &csr(&rsa_key(2048), "dev1.iot.example"),
    )
    .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // the second device is unaffected
    let resp = est::enroll_for_peer(
        &kms,
        Some(&enrolled[1]),
        &csr(&rsa_key(2048), "dev2.iot.example"),
    )
    .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

// ── SCEP ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scep_get_ca_caps_is_fips_conformant() -> KResult<()> {
    for (allow_renewal, expected) in [
        (true, &b"POSTPKIOperation\nSHA-256\nAES\nRenewal"[..]),
        // `Renewal` is advertised only when `RenewalReq` is accepted
        (false, &b"POSTPKIOperation\nSHA-256\nAES"[..]),
    ] {
        let (kms, _) = make_kms(false, true, allow_renewal).await?;
        let app = app!(kms);
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/scep?operation=GetCACaps")
                .to_request(),
        )
        .await;
        let (status, body, headers) = body_of(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h(&headers, "content-type"), "text/plain");
        assert_eq!(body, expected);
    }
    Ok(())
}

/// The Windows MDM (NDES) client appends `/pkiclient.exe` to the profile URL.
#[tokio::test]
async fn scep_is_served_under_pkiclient_exe() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let caps = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/scep/pkiclient.exe?operation=GetCACaps&message=default")
            .to_request(),
    )
    .await;
    let (status, body, _) = body_of(caps).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"POSTPKIOperation\nSHA-256\nAES\nRenewal");
    let cert = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/scep/pkiclient.exe?operation=GetCACert&message=default")
            .to_request(),
    )
    .await;
    let (status, body, _) = body_of(cert).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, ca.to_der().unwrap());
    let post = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/scep/pkiclient.exe?operation=Unknown")
            .to_request(),
    )
    .await;
    assert_eq!(post.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn scep_get_ca_cert_returns_raw_der() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/scep?operation=GetCACert")
            .to_request(),
    )
    .await;
    let (status, body, headers) = body_of(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h(&headers, "content-type"), "application/x-x509-ca-cert");
    assert_eq!(body, ca.to_der().unwrap());
    Ok(())
}

struct Outcome {
    attrs: ScepAttrs,
    certificate: Option<X509>,
}

/// Fixed `senderNonce` of the test SCEP requests.
const SENDER_NONCE: [u8; NONCE_LEN] = [0x5A_u8; NONCE_LEN];

/// Build a signed SCEP `pkiMessage` carrying `csr` encrypted to `ca`.
fn pki_message(
    ca: &X509,
    signer_cert: &X509,
    signer_key: &PKey<Private>,
    csr: &X509Req,
    message_type: u8,
    transaction_id: &str,
) -> Vec<u8> {
    let envelope = envelope_for_recipient(ca, &csr.to_der().unwrap()).unwrap();
    build_signed_pkimessage(
        signer_cert,
        signer_key,
        &envelope,
        &ScepAttrs {
            transaction_id: transaction_id.to_owned(),
            message_type,
            pki_status: None,
            fail_info: None,
            sender_nonce: SENDER_NONCE,
            recipient_nonce: None,
        },
    )
    .unwrap()
}

/// A `PKCSReq` with the right challenge, signed by a self-signed bootstrap certificate.
fn scep_pkcs_req_message(ca: &X509, key: &PKey<Private>, cn: &str) -> Vec<u8> {
    pki_message(
        ca,
        &self_signed(key, cn),
        key,
        &pkcs_req_csr(key, cn, CHALLENGE),
        MESSAGE_TYPE_PKCS_REQ,
        "TX-PKCS-REQ",
    )
}

/// Send one `PKIOperation` the way a SCEP client does and decode the `CertRep`.
async fn scep_roundtrip<S, B>(
    app: &S,
    ca: &X509,
    (signer_cert, signer_key): (&X509, &PKey<Private>),
    csr: &X509Req,
    message_type: u8,
    transaction_id: &str,
    via_get: bool,
) -> Outcome
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let message = pki_message(
        ca,
        signer_cert,
        signer_key,
        csr,
        message_type,
        transaction_id,
    );
    let req = if via_get {
        let encoded = url::form_urlencoded::byte_serialize(STANDARD.encode(&message).as_bytes())
            .collect::<String>();
        test::TestRequest::get()
            .uri(&format!("/scep?operation=PKIOperation&message={encoded}"))
            .to_request()
    } else {
        test::TestRequest::post()
            .uri("/scep?operation=PKIOperation")
            .insert_header(("Content-Type", "application/x-pki-message"))
            .set_payload(message)
            .to_request()
    };
    let (status, body, headers) = body_of(test::call_service(app, req).await).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(h(&headers, "content-type"), "application/x-pki-message");

    let parsed = parse_signed_pkimessage(&body).unwrap();
    assert_eq!(parsed.signer_cert.to_der().unwrap(), ca.to_der().unwrap());
    assert_eq!(parsed.attrs.message_type, MESSAGE_TYPE_CERT_REP);
    assert_eq!(parsed.attrs.transaction_id, transaction_id);
    assert_eq!(parsed.attrs.recipient_nonce, Some(SENDER_NONCE));
    let certificate = if parsed.attrs.pki_status == Some(PKI_STATUS_SUCCESS) {
        let inner = decrypt_envelope(&parsed.content, signer_key, signer_cert).unwrap();
        Some(certs_of(&inner).remove(0))
    } else {
        assert!(
            parsed.content.is_empty(),
            "failure CertRep carries no content"
        );
        None
    };
    Outcome {
        attrs: parsed.attrs,
        certificate,
    }
}

fn pkcs_req_csr(key: &PKey<Private>, cn: &str, challenge: &str) -> X509Req {
    csr_with_challenge_password(&csr(key, cn), key, challenge).unwrap()
}

#[tokio::test]
async fn scep_pkcsreq_with_challenge_issues_certificate() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, "dev1.iot.example");
    for (tx, via_get) in [("TX-POST-1", false), ("TX-GET-1", true)] {
        let outcome = scep_roundtrip(
            &app,
            &ca,
            (&bootstrap, &key),
            &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
            MESSAGE_TYPE_PKCS_REQ,
            tx,
            via_get,
        )
        .await;
        assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_SUCCESS));
        let cert = outcome.certificate.unwrap();
        assert_issued_by(&cert, &ca);
        assert!(cert.public_key().unwrap().public_eq(&key));
    }
    Ok(())
}

fn default_policy(conf: &mut crate::config::ClapConfig) {
    conf.kmip_policy.policy_id = Some("DEFAULT".to_owned());
}

#[tokio::test]
async fn est_simpleenroll_under_default_kmip_policy_requires_compliant_keys() -> KResult<()> {
    let (kms, ca) = make_kms_with(true, false, true, default_policy).await?;
    let app = app!(kms);
    let (status, body, _) = est_enroll(
        &app,
        &csr(&rsa_key(2048), "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        String::from_utf8_lossy(&body).contains("RSA key size not in allowed set: 2048"),
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body, _) = est_enroll(
        &app,
        &csr(&rsa_key(3072), "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_issued_by(&certs_of(&STANDARD.decode(&body).unwrap())[0], &ca);
    Ok(())
}

#[tokio::test]
async fn scep_pkcsreq_under_default_kmip_policy_requires_compliant_keys() -> KResult<()> {
    let (kms, ca) = make_kms_with(false, true, true, default_policy).await?;
    let app = app!(kms);
    for (bits, expected) in [(3072, PKI_STATUS_SUCCESS), (2048, PKI_STATUS_FAILURE)] {
        let key = rsa_key(bits);
        let outcome = scep_roundtrip(
            &app,
            &ca,
            (&self_signed(&key, "dev1.iot.example"), &key),
            &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
            MESSAGE_TYPE_PKCS_REQ,
            &format!("TX-POLICY-{bits}"),
            false,
        )
        .await;
        assert_eq!(outcome.attrs.pki_status, Some(expected), "RSA-{bits}");
    }
    Ok(())
}

/// Captures of the native macOS SCEP client (`mise run test:scep-apple`) must stay parseable by
/// the server: a signed `PKCSReq` whose envelope decrypts with the test CA to an RSA-2048 CSR
/// carrying the challenge and the profile's CN.
#[tokio::test]
async fn apple_scep_fixtures_parse() {
    init_openssl_providers_for_tests();
    let mut captures = 0;
    let fixtures = std::fs::read_dir("../../test_data/scep/apple").expect(
        "test_data/scep/apple missing: initialise the test_data submodule \
         (`git submodule update --init test_data`)",
    );
    for entry in fixtures {
        let dir = entry.unwrap().path();
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let ca = X509::from_pem(&read("ca.crt")).unwrap();
        let ca_key = PKey::private_key_from_pem(&read("ca.key")).unwrap();

        let parsed = parse_signed_pkimessage(&read("pkcsreq.der")).unwrap();
        assert_eq!(
            parsed.attrs.message_type,
            MESSAGE_TYPE_PKCS_REQ,
            "{}",
            dir.display()
        );
        assert!(!parsed.attrs.transaction_id.is_empty());
        let csr =
            X509Req::from_der(&decrypt_envelope(&parsed.content, &ca_key, &ca).unwrap()).unwrap();
        let key = csr.public_key().unwrap();
        assert!(csr.verify(&key).unwrap(), "CSR proof of possession");
        assert_eq!(key.bits(), 2048);
        assert_eq!(csr_challenge_password(&csr).as_deref(), Some(CHALLENGE));
        let cn = csr
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_slice();
        assert_eq!(cn, b"mac-01.iot.example");

        // Renewal capture (if any) is observational: it only has to be a valid pkiMessage.
        if dir.join("renewal.der").exists() {
            let renewal = parse_signed_pkimessage(&read("renewal.der")).unwrap();
            assert!(
                [MESSAGE_TYPE_PKCS_REQ, MESSAGE_TYPE_RENEWAL_REQ]
                    .contains(&renewal.attrs.message_type)
            );
        }
        captures += 1;
    }
    assert!(
        captures > 0,
        "no Apple SCEP capture under test_data/scep/apple"
    );
}

#[tokio::test]
async fn scep_pkcsreq_rejects_wrong_or_missing_challenge_and_template_violations() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, "dev1.iot.example");
    let cases = [
        pkcs_req_csr(&key, "dev1.iot.example", "WrongSecret"),
        csr(&key, "dev1.iot.example"), // no challengePassword at all
        pkcs_req_csr(&key, "evil.example.com", CHALLENGE), // violates the CN pattern
    ];
    for (i, case) in cases.iter().enumerate() {
        let outcome = scep_roundtrip(
            &app,
            &ca,
            (&bootstrap, &key),
            case,
            MESSAGE_TYPE_PKCS_REQ,
            &format!("TX-BAD-{i}"),
            false,
        )
        .await;
        assert_eq!(
            outcome.attrs.pki_status,
            Some(PKI_STATUS_FAILURE),
            "case {i}"
        );
        assert_eq!(
            outcome.attrs.fail_info,
            Some(FAIL_INFO_BAD_REQUEST),
            "case {i}"
        );
        assert!(outcome.certificate.is_none());
    }
    Ok(())
}

/// Enroll a device through SCEP and return its key and certificate.
async fn enroll_device<S, B>(app: &S, ca: &X509, cn: &str) -> (PKey<Private>, X509)
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, cn);
    let outcome = scep_roundtrip(
        app,
        ca,
        (&bootstrap, &key),
        &pkcs_req_csr(&key, cn, CHALLENGE),
        MESSAGE_TYPE_PKCS_REQ,
        "TX-ENROLL",
        false,
    )
    .await;
    (key, outcome.certificate.unwrap())
}

#[tokio::test]
async fn scep_renewal_without_challenge_succeeds_for_active_certificate() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let (key, cert) = enroll_device(&app, &ca, "dev1.iot.example").await;

    // RenewalReq: fresh key pair, same Subject, no challengePassword, signed with the
    // currently valid certificate.
    let new_key = rsa_key(2048);
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&cert, &key),
        &csr(&new_key, "dev1.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-RENEW",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_SUCCESS));
    let renewed = outcome.certificate.unwrap();
    assert_issued_by(&renewed, &ca);
    assert!(renewed.public_key().unwrap().public_eq(&new_key));

    // A renewal cannot change the identity.
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&cert, &key),
        &csr(&new_key, "dev2.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-RENEW-ID",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcome.attrs.fail_info, Some(FAIL_INFO_BAD_REQUEST));
    Ok(())
}

#[tokio::test]
async fn scep_renewal_rejects_foreign_and_revoked_signers() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let (key, cert) = enroll_device(&app, &ca, "dev1.iot.example").await;

    // signed by a self-signed (not CA issued) certificate
    let foreign_key = rsa_key(2048);
    let foreign = self_signed(&foreign_key, "dev1.iot.example");
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&foreign, &foreign_key),
        &csr(&foreign_key, "dev1.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-FOREIGN",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcome.attrs.fail_info, Some(FAIL_INFO_BAD_CERT_ID));

    // signed by a revoked certificate
    let serial_hex = cert
        .serial_number()
        .to_bn()
        .unwrap()
        .to_hex_str()
        .unwrap()
        .to_string();
    let (uid, _, _) = Box::pin(kms.database.find_certificate_by_serial(
        CA_UID,
        &serial_hex,
        kms.vendor_id(),
    ))
    .await?
    .expect("issued certificate is tracked");
    let owner: UserId = kms.params.default_username.clone().into();
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid)),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        &owner,
    )
    .await?;
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&cert, &key),
        &csr(&key, "dev1.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-REVOKED",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcome.attrs.fail_info, Some(FAIL_INFO_BAD_CERT_ID));
    Ok(())
}

#[tokio::test]
async fn scep_renewal_can_be_disabled() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, false).await?;
    let app = app!(kms);
    let (key, cert) = enroll_device(&app, &ca, "dev1.iot.example").await;
    let message = pki_message(
        &ca,
        &cert,
        &key,
        &csr(&key, "dev1.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-OFF",
    );
    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .set_payload(message)
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn est_simpleenroll_requires_client_certificate_when_configured() -> KResult<()> {
    let (kms, _) = make_kms_with(true, false, true, |c| {
        c.est.est_require_client_cert = true;
    })
    .await?;
    let app = app!(kms);
    let csr = csr(&rsa_key(2048), "dev1.iot.example");
    // valid Basic credentials must not be honoured when a client certificate is mandatory
    let (status, _, headers) =
        est_enroll(&app, &csr, Some(basic_auth("testuser", "testpass"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get("www-authenticate").is_none());
    Ok(())
}

#[tokio::test]
async fn est_simplereenroll_route_never_accepts_basic_credentials() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let csr = csr(&rsa_key(2048), "dev1.iot.example");
    let req = test::TestRequest::post()
        .uri("/.well-known/est/simplereenroll")
        .insert_header(basic_auth("testuser", "testpass"))
        .set_payload(STANDARD.encode(csr.to_der().unwrap()))
        .to_request();
    let (status, _, _) = body_of(test::call_service(&app, req).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn scep_renewal_challenge_does_not_replace_a_ca_issued_signer() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let foreign = self_signed(&key, "dev1.iot.example");
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&foreign, &key),
        &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-CHALLENGE-RENEWAL",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcome.attrs.fail_info, Some(FAIL_INFO_BAD_CERT_ID));
    Ok(())
}

#[tokio::test]
async fn startup_rejects_unsafe_enrollment_configuration() {
    type Tweak = fn(&mut crate::config::ClapConfig);
    init_openssl_providers_for_tests();
    let cases: [(&str, Tweak); 8] = [
        ("est without CA", |c| c.est.est_ca_uid = None),
        ("scep without CA", |c| c.scep.scep_ca_uid = None),
        ("scep blank challenge", |c| {
            c.scep.scep_challenge_password = Some("  ".to_owned());
        }),
        ("est basic without credentials", |c| {
            c.est.est_bootstrap_password = None;
        }),
        ("est basic bootstrap without TLS", |c| {
            c.tls = TlsConfig::default();
        }),
        ("est mutual TLS without a client CA", |c| {
            c.est.est_require_client_cert = true;
            c.tls.clients_ca_cert_file = None;
        }),
        ("unknown template", |c| {
            c.scep.scep_template = Some("missing".to_owned());
        }),
        ("weak template", |c| {
            c.templates.get_mut("iot_device").unwrap().min_rsa_key_bits = 1024;
        }),
    ];
    for (name, tweak) in cases {
        let mut conf = config(true, true, true);
        tweak(&mut conf);
        assert!(
            ServerParams::try_from(conf).is_err(),
            "{name} must be refused"
        );
    }
    ServerParams::try_from(config(true, true, true)).unwrap();

    // The enrollment service identity is reserved: no configured principal may use it.
    let reserved: [(&str, Tweak); 2] = [
        ("reserved default_username", |c| {
            c.default_username = ENROLLMENT_SERVICE_USER.to_owned();
        }),
        ("reserved crypto officer", |c| {
            c.roles.crypto_officer_users = Some(vec![ENROLLMENT_SERVICE_USER.to_owned()]);
        }),
    ];
    for (name, tweak) in reserved {
        let mut conf = config(true, true, true);
        tweak(&mut conf);
        let err = ServerParams::try_from(conf).expect_err(name).to_string();
        assert!(
            err.contains("reserved enrollment service identity"),
            "{name}: {err}"
        );
    }
}

#[tokio::test]
async fn issued_certificate_is_owned_by_the_ca_owner_not_the_service_identity() -> KResult<()> {
    // A CA owner distinct from `default_username` tells the CA-owner path apart from the
    // former default-user behaviour.
    const CA_OWNER: &str = "ca-owner@example.com";
    let (kms, ca) = make_scep_kms_with_ca_owner(CA_OWNER).await?;
    let app = app!(kms);
    let (_, cert) = enroll_device(&app, &ca, "dev1.iot.example").await;
    let serial_hex = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    let (uid, _, _) = Box::pin(kms.database.find_certificate_by_serial(
        CA_UID,
        &serial_hex,
        kms.vendor_id(),
    ))
    .await?
    .expect("issued certificate is tracked");
    let owm = kms.database.retrieve_object(&uid).await?.expect("stored");
    assert_eq!(owm.owner_id(), CA_OWNER);
    Ok(())
}

/// UIDs of every certificate object in the database.
async fn certificate_uids(kms: &KMS) -> KResult<HashSet<String>> {
    Ok(kms
        .database
        .list_uids_for_tags(&HashSet::from([SYSTEM_TAG_CERTIFICATE.to_owned()]))
        .await?)
}

#[tokio::test]
async fn enrollment_without_certify_grant_fails_closed() -> KResult<()> {
    let (kms, ca) = make_kms(true, true, true).await?;
    undelegate_ca_key(&kms).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let before = certificate_uids(&kms).await?;

    let (status, body, _) = est_enroll(
        &app,
        &csr(&key, "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert!(
        !status.is_success(),
        "EST must not issue without the grant: {status} {}",
        String::from_utf8_lossy(&body)
    );

    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .insert_header(("Content-Type", "application/x-pki-message"))
        .set_payload(scep_pkcs_req_message(&ca, &key, "dev1.iot.example"))
        .to_request();
    let (status, body, _) = body_of(test::call_service(&app, req).await).await;
    // unauthenticated caller: a fixed message, no CA / key UID or permission detail (S105)
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, b"the enrollment CA is not available");

    assert_eq!(
        certificate_uids(&kms).await?,
        before,
        "a refused enrollment must not create any certificate object"
    );
    Ok(())
}

// ── abuse controls and hardening ─────────────────────────────────────────────

/// Ten wrong Basic credentials lock the client out; even the right ones are then refused until
/// the delay has passed.
#[tokio::test]
async fn est_repeated_wrong_credentials_lock_the_client_out() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let csr = csr(&rsa_key(2048), "dev1.iot.example");
    for _ in 0..10 {
        let (status, _, _) = est_enroll(&app, &csr, Some(basic_auth("testuser", "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, headers) =
        est_enroll(&app, &csr, Some(basic_auth("testuser", "testpass"))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
    Ok(())
}

/// A request without credentials is the first leg of the RFC 7030 challenge, not a guess: it
/// never counts towards the lockout.
#[tokio::test]
async fn est_requests_without_credentials_do_not_lock_the_client_out() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let csr = csr(&rsa_key(2048), "dev1.iot.example");
    for _ in 0..25 {
        let (status, _, _) = est_enroll(&app, &csr, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = est_enroll(&app, &csr, Some(basic_auth("testuser", "testpass"))).await;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn enrollment_bodies_over_the_limit_are_refused() -> KResult<()> {
    let (kms, _) = make_kms(true, true, true).await?;
    let app = app!(kms);
    let big = vec![b'A'; crate::routes::enrollment::MAX_ENROLLMENT_BODY + 1];

    let req = test::TestRequest::post()
        .uri("/.well-known/est/simpleenroll")
        .insert_header(basic_auth("testuser", "testpass"))
        .set_payload(big.clone())
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .set_payload(big)
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    Ok(())
}

/// A captured, authenticated `PKCSReq` cannot be replayed to make the CA issue again.
#[tokio::test]
async fn scep_replayed_message_is_refused() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, "dev1.iot.example");
    let mut outcomes = Vec::new();
    // Same signer, transactionID and sender nonce: the second message is a replay.
    for _ in 0..2 {
        outcomes.push(
            scep_roundtrip(
                &app,
                &ca,
                (&bootstrap, &key),
                &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
                MESSAGE_TYPE_PKCS_REQ,
                "TX-REPLAY",
                false,
            )
            .await,
        );
    }
    assert_eq!(outcomes[0].attrs.pki_status, Some(PKI_STATUS_SUCCESS));
    assert_eq!(outcomes[1].attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcomes[1].attrs.fail_info, Some(FAIL_INFO_BAD_REQUEST));
    assert!(outcomes[1].certificate.is_none());
    Ok(())
}

/// A captured `PKCSReq` envelope re-signed by another certificate, with a fresh transactionID
/// and sender nonce, is still a replay: it must not make the CA issue again (nor reset the
/// lockout) without knowledge of the challenge.
#[tokio::test]
async fn scep_resigned_envelope_is_refused() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let post = |message: Vec<u8>| {
        test::TestRequest::post()
            .uri("/scep?operation=PKIOperation")
            .set_payload(message)
            .to_request()
    };
    let captured = scep_pkcs_req_message(&ca, &rsa_key(2048), "dev1.iot.example");
    let (status, body, _) = body_of(test::call_service(&app, post(captured.clone())).await).await;
    assert_eq!(status, StatusCode::OK);
    let first = parse_signed_pkimessage(&body).unwrap();
    assert_eq!(first.attrs.pki_status, Some(PKI_STATUS_SUCCESS));

    let attacker_key = rsa_key(2048);
    let resigned = build_signed_pkimessage(
        &self_signed(&attacker_key, "attacker"),
        &attacker_key,
        &parse_signed_pkimessage(&captured).unwrap().content,
        &ScepAttrs {
            transaction_id: "TX-RESIGNED".to_owned(),
            message_type: MESSAGE_TYPE_PKCS_REQ,
            pki_status: None,
            fail_info: None,
            sender_nonce: [0xA5_u8; NONCE_LEN],
            recipient_nonce: None,
        },
    )
    .unwrap();
    let (status, body, _) = body_of(test::call_service(&app, post(resigned)).await).await;
    assert_eq!(status, StatusCode::OK);
    let replay = parse_signed_pkimessage(&body).unwrap();
    assert_eq!(replay.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(replay.attrs.fail_info, Some(FAIL_INFO_BAD_REQUEST));
    assert!(replay.content.is_empty());
    Ok(())
}

/// Every failure after the envelope is parsed reports `badRequest`, so the `failInfo` does not
/// tell an undecryptable envelope from a wrong challenge.
#[tokio::test]
async fn scep_failure_reporting_does_not_depend_on_the_envelope_outcome() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, "dev1.iot.example");

    // an envelope that is encrypted to another recipient cannot be decrypted by the CA
    let other_ca = self_signed(&rsa_key(2048), "other-ca");
    let undecryptable = pki_message(
        &other_ca,
        &bootstrap,
        &key,
        &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
        MESSAGE_TYPE_PKCS_REQ,
        "TX-UNDECRYPTABLE",
    );
    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .set_payload(undecryptable)
        .to_request();
    let (status, body, _) = body_of(test::call_service(&app, req).await).await;
    assert_eq!(status, StatusCode::OK);
    let undecryptable = parse_signed_pkimessage(&body).unwrap();

    let wrong_challenge = scep_roundtrip(
        &app,
        &ca,
        (&bootstrap, &key),
        &pkcs_req_csr(&key, "dev1.iot.example", "WrongSecret"),
        MESSAGE_TYPE_PKCS_REQ,
        "TX-WRONG-CHALLENGE",
        false,
    )
    .await;
    assert_eq!(undecryptable.attrs.fail_info, Some(FAIL_INFO_BAD_REQUEST));
    assert_eq!(
        undecryptable.attrs.fail_info,
        wrong_challenge.attrs.fail_info
    );
    Ok(())
}

/// The `transactionID` is echoed and logged: an overlong one is refused before any work.
#[tokio::test]
async fn scep_overlong_transaction_id_is_refused() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let message = pki_message(
        &ca,
        &self_signed(&key, "dev1.iot.example"),
        &key,
        &pkcs_req_csr(&key, "dev1.iot.example", CHALLENGE),
        MESSAGE_TYPE_PKCS_REQ,
        &"T".repeat(200),
    );
    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .set_payload(message)
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

/// A certificate that carries the enrollment marker but was not issued by the EST CA (SCEP CA,
/// previous CA key) cannot bootstrap an EST enrollment: its state cannot be checked here.
#[tokio::test]
async fn est_simpleenroll_refuses_an_enrolled_certificate_issued_elsewhere() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let foreign_key = rsa_key(2048);
    let build = |marked: bool| {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "dev9.iot.example").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(9).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&foreign_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        if marked {
            // The same extension-file mechanism the enrollment template uses to stamp it.
            let extensions = {
                let context = b.x509v3_context(None, None);
                cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::x509_extensions::parse_v3_ca_from_str(
                    &format!(
                        "[v3_ca]\ncertificatePolicies={}\n",
                        crate::core::operations::certify::template::ENROLLED_CERTIFICATE_POLICY_OID
                    ),
                    &context,
                )
                .unwrap()
            };
            for extension in extensions {
                b.append_extension(extension).unwrap();
            }
        }
        b.sign(&foreign_key, MessageDigest::sha256()).unwrap();
        b.build()
    };
    let request = csr(&rsa_key(2048), "dev9.iot.example");

    let resp = est::enroll_for_peer(&kms, Some(&build(true)), &request).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // the same certificate without the marker is an ordinary bootstrap certificate
    let resp = est::enroll_for_peer(&kms, Some(&build(false)), &request).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

/// An enrolled certificate is indexed by issuer and serial, so that renewal does not scan every
/// certificate of the CA.
#[tokio::test]
async fn enrolled_certificates_are_indexed_by_serial() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let (status, body, _) = est_enroll(
        &app,
        &csr(&rsa_key(2048), "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cert = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    let serial_hex = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    let uids = kms
        .database
        .list_uids_for_tags(&HashSet::from([crate::routes::enrollment::serial_tag(
            CA_UID,
            &serial_hex,
        )]))
        .await?;
    assert_eq!(uids.len(), 1);
    Ok(())
}

/// The serial fallback (certificates without the serial tag) checks every candidate: a copy of
/// the certificate stored under another owner and met first must not hide the genuine one (F2).
#[tokio::test]
async fn serial_fallback_is_not_blocked_by_a_planted_copy() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let (_, body, _) = est_enroll(
        &app,
        &csr(&rsa_key(2048), "dev1.iot.example"),
        Some(basic_auth("testuser", "testpass")),
    )
    .await;
    let cert = certs_of(&STANDARD.decode(&body).unwrap()).remove(0);
    let serial_hex = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    let tag = crate::routes::enrollment::serial_tag(CA_UID, &serial_hex);
    let uid = kms
        .database
        .list_uids_for_tags(&HashSet::from([tag.clone()]))
        .await?
        .into_iter()
        .next()
        .unwrap();
    let genuine = kms.database.retrieve_object(&uid).await?.unwrap();
    let mut tags = kms.database.retrieve_tags(&uid).await?;
    tags.remove(&tag);
    let mut attributes = genuine.attributes().clone();
    attributes.state = Some(State::Active);
    // Store the genuine certificate again without the tag (as before the serial index), after
    // a copy owned by another user, so that the scan meets the copy first.
    kms.database.delete(&uid).await?;
    kms.database
        .create(
            Some("planted-copy".to_owned()),
            &UserId::from("mallory@example.com"),
            genuine.object(),
            &attributes,
            &tags,
        )
        .await?;
    kms.database
        .create(
            Some(uid),
            genuine.owner_id(),
            genuine.object(),
            &attributes,
            &tags,
        )
        .await?;
    let resp =
        est::enroll_for_peer(&kms, Some(&cert), &csr(&rsa_key(2048), "dev1.iot.example")).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

/// A `PKCSReq` signed by a key other than the CSR key is accepted: RFC 8894 §2.3 only says
/// SHOULD, and the native macOS client signs with a separate "MDM SCEP SIGNER" key (see the
/// `test_data/scep/apple` capture). Re-signed captures are stopped by the envelope replay key.
#[tokio::test]
async fn scep_pkcsreq_signer_key_may_differ_from_the_csr_key() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let other = rsa_key(2048);
    let outcome = scep_roundtrip(
        &app,
        &ca,
        (&self_signed(&other, "dev1.iot.example"), &other),
        &pkcs_req_csr(&rsa_key(2048), "dev1.iot.example", CHALLENGE),
        MESSAGE_TYPE_PKCS_REQ,
        "TX-OTHER-KEY",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_SUCCESS));
    Ok(())
}

/// Message types the CA does not process get a plain `400` before any CA work and count
/// towards the lockout (S102).
#[tokio::test]
async fn scep_unprocessed_message_types_are_refused_early_and_counted() -> KResult<()> {
    /// `GetCert` (RFC 8894 §3.2.1.2), not implemented.
    const GET_CERT: u8 = 21;
    // renewal disabled
    let (kms, ca) = make_kms(false, true, false).await?;
    let app = app!(kms);
    let key = rsa_key(2048);
    let bootstrap = self_signed(&key, "dev1.iot.example");
    let post = |message: Vec<u8>| {
        test::TestRequest::post()
            .uri("/scep?operation=PKIOperation")
            .set_payload(message)
            .to_request()
    };
    for (i, message_type) in [GET_CERT, MESSAGE_TYPE_RENEWAL_REQ]
        .into_iter()
        .cycle()
        .take(10)
        .enumerate()
    {
        let message = pki_message(
            &ca,
            &bootstrap,
            &key,
            &csr(&key, "dev1.iot.example"),
            message_type,
            &format!("TX-UNPROCESSED-{i}"),
        );
        let (status, _, headers) = body_of(test::call_service(&app, post(message)).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "message {i}");
        assert_ne!(h(&headers, "content-type"), "application/x-pki-message");
    }
    let message = scep_pkcs_req_message(&ca, &key, "dev1.iot.example");
    assert_eq!(
        test::call_service(&app, post(message)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

/// Only a challenge-authenticated enrollment clears the failure counter: a successful renewal
/// does not (S103).
#[tokio::test]
async fn scep_renewal_does_not_clear_the_lockout() -> KResult<()> {
    let (kms, ca) = make_kms(false, true, true).await?;
    let app = app!(kms);
    let (key, cert) = enroll_device(&app, &ca, "dev1.iot.example").await;
    let bootstrap = self_signed(&key, "dev1.iot.example");
    let wrong_challenge = pkcs_req_csr(&key, "dev1.iot.example", "WrongSecret");
    for i in 0..10 {
        if i == 9 {
            let renewal = scep_roundtrip(
                &app,
                &ca,
                (&cert, &key),
                &csr(&rsa_key(2048), "dev1.iot.example"),
                MESSAGE_TYPE_RENEWAL_REQ,
                "TX-RENEW-BETWEEN",
                false,
            )
            .await;
            assert_eq!(renewal.attrs.pki_status, Some(PKI_STATUS_SUCCESS));
        }
        let outcome = scep_roundtrip(
            &app,
            &ca,
            (&bootstrap, &key),
            &wrong_challenge,
            MESSAGE_TYPE_PKCS_REQ,
            &format!("TX-WRONG-{i}"),
            false,
        )
        .await;
        assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    }
    let req = test::TestRequest::post()
        .uri("/scep?operation=PKIOperation")
        .set_payload(scep_pkcs_req_message(&ca, &key, "dev1.iot.example"))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}
