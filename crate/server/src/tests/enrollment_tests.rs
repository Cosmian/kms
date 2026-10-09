//! EST (RFC 7030) and SCEP (RFC 8894) enrollment endpoint tests.
//!
//! The endpoints are exercised through an in-process actix application backed by a real
//! `KMS` instance (temporary `SQLite` database) and a CA created with KMIP `Certify`. The SCEP
//! client side (signed `pkiMessage`, `pkcsPKIEnvelope`) is built with the same CMS helpers
//! the server uses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use actix_web::{
    App,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test,
    web::Data,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
        kmip_2_1::{
            extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_operations::{Certify, Revoke},
            kmip_types::{
                CertificateAttributes, CryptographicAlgorithm, UniqueIdentifier, VendorAttribute,
                VendorAttributeValue,
            },
        },
    },
    cosmian_kms_crypto::openssl::{
        csr_attrs::csr_with_challenge_password,
        scep_cms::{
            FAIL_INFO_BAD_CERT_ID, FAIL_INFO_BAD_REQUEST, MESSAGE_TYPE_CERT_REP,
            MESSAGE_TYPE_PKCS_REQ, MESSAGE_TYPE_RENEWAL_REQ, NONCE_LEN, PKI_STATUS_FAILURE,
            PKI_STATUS_SUCCESS, ScepAttrs, build_signed_pkimessage, decrypt_envelope,
            envelope_for_recipient, parse_signed_pkimessage,
        },
    },
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
    config::{EstConfig, ScepConfig, ServerParams},
    core::{KMS, operations::certify::template::CertTemplate},
    middlewares::UserId,
    openssl_providers::init_openssl_providers_for_tests,
    result::KResult,
    routes::{est, scep},
    tests::test_utils::https_clap_config,
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

/// Start a KMS with the enrollment endpoints configured and create the CA.
async fn make_kms(
    est_enabled: bool,
    scep_enabled: bool,
    allow_renewal: bool,
) -> KResult<(Arc<KMS>, X509)> {
    cosmian_logger::log_init(None);
    init_openssl_providers_for_tests();
    let kms = Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(config(
            est_enabled,
            scep_enabled,
            allow_renewal,
        ))?))
        .await?,
    );
    let owner: UserId = kms.params.default_username.clone().into();
    let attrs = Attributes {
        unique_identifier: Some(UniqueIdentifier::TextString(CA_UID.to_owned())),
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
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
    let ca_cert = crate::routes::enrollment::load_ca_chain(&kms, CA_UID)
        .await?
        .remove(0);
    Ok((kms, ca_cert))
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
    ] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/.well-known/est/simpleenroll")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

#[tokio::test]
async fn est_simpleenroll_enforces_template() -> KResult<()> {
    let (kms, _) = make_kms(true, false, true).await?;
    let app = app!(kms);
    let auth = || Some(basic_auth("testuser", "testpass"));
    // key too small
    let (status, body, _) =
        est_enroll(&app, &csr(&rsa_key(1024), "dev1.iot.example"), auth()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body).contains("below the template minimum"));
    // CN outside the allowed pattern
    let (status, body, _) =
        est_enroll(&app, &csr(&rsa_key(2048), "evil.example.com"), auth()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body).contains("does not match"));
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

// ── SCEP ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scep_get_ca_caps_is_fips_conformant() -> KResult<()> {
    let (kms, _) = make_kms(false, true, true).await?;
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
    assert_eq!(body, b"POSTPKIOperation\nSHA-256\nAES\nRenewal");
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

/// Send one `PKIOperation` the way a SCEP client does and decode the `CertRep`.
#[allow(clippy::too_many_arguments)]
async fn scep_roundtrip<S, B>(
    app: &S,
    ca: &X509,
    signer_cert: &X509,
    signer_key: &PKey<Private>,
    csr: &X509Req,
    message_type: u8,
    transaction_id: &str,
    via_get: bool,
) -> Outcome
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let envelope = envelope_for_recipient(ca, &csr.to_der().unwrap()).unwrap();
    let sender_nonce = [0x5A_u8; NONCE_LEN];
    let message = build_signed_pkimessage(
        signer_cert,
        signer_key,
        &envelope,
        &ScepAttrs {
            transaction_id: transaction_id.to_owned(),
            message_type,
            pki_status: None,
            fail_info: None,
            sender_nonce,
            recipient_nonce: None,
        },
    )
    .unwrap();
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
    assert_eq!(parsed.attrs.recipient_nonce, Some(sender_nonce));
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
            &bootstrap,
            &key,
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
            &bootstrap,
            &key,
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
        &bootstrap,
        &key,
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
        &cert,
        &key,
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
        &cert,
        &key,
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
        &foreign,
        &foreign_key,
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
        &cert,
        &key,
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
    let outcome = scep_roundtrip(
        &app,
        &ca,
        &cert,
        &key,
        &csr(&key, "dev1.iot.example"),
        MESSAGE_TYPE_RENEWAL_REQ,
        "TX-OFF",
        false,
    )
    .await;
    assert_eq!(outcome.attrs.pki_status, Some(PKI_STATUS_FAILURE));
    assert_eq!(outcome.attrs.fail_info, Some(FAIL_INFO_BAD_REQUEST));
    Ok(())
}
