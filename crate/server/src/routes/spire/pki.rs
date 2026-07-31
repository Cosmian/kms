//! SPIRE-compatible PKI engine — sign-intermediate.
//!
//! Route:
//!   `POST /root/sign-intermediate` — sign a CSR with the configured CA key
//!
//! The CA private key is located in the KMS by the tag `vault_pki_ca_key_label`
//! configured in `ServerParams`.
//!
//! Request:
//!   `{ "csr": "<PEM>", "uri_sans": ["spiffe://..."], "ttl": "8760h" }`
//!
//! The signed certificate's Subject and SANs come from the CSR itself; the
//! `Certify` operation signs the CSR as presented. `common_name`/`organization`/
//! `country` are therefore not accepted — SPIRE encodes them in the CSR.
//!
//! Response:
//!   `{ "data": { "certificate": "<PEM>", "issuing_ca": "<PEM>",
//!     "ca_chain": ["<PEM>", ...] } }`

use std::sync::Arc;

use actix_web::{
    HttpRequest, route,
    web::{Bytes, Data, Json},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::Certify,
        kmip_types::{CertificateRequestType, LinkType, LinkedObjectIdentifier},
    },
    cosmian_kms_crypto::openssl::kmip_certificate_to_openssl,
};
use cosmian_logger::{debug, trace};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::{
    core::KMS,
    routes::spire::error::{SpireApiError, SpireResult},
};

// ── Request / Response types ──────────────────────────────────────────────────

/// Deserialize a field that may arrive as either a JSON string (comma-separated)
/// or a JSON array of strings — the Vault PKI API accepts both, and SPIRE's vault
/// `UpstreamAuthority` plugin sends `uri_sans` as a plain string.
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            // Split comma-separated values, trim whitespace
            Ok(v.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect())
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

#[derive(Deserialize)]
pub(crate) struct SignIntermediateRequest {
    /// PEM-encoded CSR from the workload (SPIRE SVID or intermediate CA).
    ///
    /// The signed certificate's Subject and SANs are taken **from this CSR** —
    /// the KMS `Certify` operation signs the CSR as presented. SPIRE builds the
    /// CSR with the correct Subject/URI-SANs before calling this endpoint, so no
    /// server-side Subject construction is performed.
    pub csr: String,
    /// SPIFFE URI SANs — accepts a JSON string (comma-separated) or array.
    /// The Vault Go SDK / SPIRE vault plugin sends this as a plain string.
    ///
    /// Used only to reject requests that carry no SPIFFE identity; the actual
    /// SANs on the signed certificate come from the CSR.
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub uri_sans: Vec<String>,
    /// Certificate validity duration (e.g. `"8760h"`, `"1h"`, `"3600s"`, `"365d"`).
    /// Parsed and forwarded to the KMS `Certify` operation as `requested_validity_days`.
    #[serde(default)]
    pub ttl: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct SignIntermediateData {
    /// Signed certificate PEM.
    pub certificate: String,
    /// Issuing CA certificate PEM.
    pub issuing_ca: String,
    /// Full chain: `[issuing_ca, intermediate, ...]` — root excluded.
    pub ca_chain: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct SignIntermediateResponse {
    pub data: SignIntermediateData,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a Vault-format TTL string into a number of days (ceiling).
///
/// Accepted formats:
/// - `"8760h"` — hours
/// - `"3600s"` — seconds
/// - `"365d"` — days
/// - `"3600"` — bare number treated as seconds
///
/// Returns `None` when the input is empty or unparsable.
#[allow(clippy::option_if_let_else)]
fn parse_ttl_days(ttl: &str) -> Option<i32> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return None;
    }
    let (n_str, unit) = if let Some(rest) = ttl.strip_suffix('h') {
        (rest, 'h')
    } else if let Some(rest) = ttl.strip_suffix('s') {
        (rest, 's')
    } else if let Some(rest) = ttl.strip_suffix('d') {
        (rest, 'd')
    } else {
        (ttl, 's') // bare integer → treat as seconds
    };
    let n: u64 = n_str.trim().parse().ok()?;
    let days: u64 = match unit {
        'h' => n.div_ceil(24),
        'd' => n,
        _ => n.div_ceil(86400), // seconds
    };
    i32::try_from(days).ok()
}

/// Convert an X509 DER certificate to a PEM string.
fn cert_to_pem(cert: &X509) -> Result<String, SpireApiError> {
    let pem_bytes = cert
        .to_pem()
        .map_err(|e| SpireApiError::InternalError(format!("X509 to PEM failed: {e}")))?;
    String::from_utf8(pem_bytes)
        .map_err(|e| SpireApiError::InternalError(format!("PEM utf8 error: {e}")))
}

/// Find the CA private key UID by its configured label tag.
async fn find_ca_private_key_uid(
    kms: &KMS,
    label: &str,
    user: &str,
) -> Result<String, SpireApiError> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };
    filter
        .set_tags(kms.vendor_id(), [label])
        .map_err(|e| SpireApiError::InternalError(format!("tag filter error: {e}")))?;

    let results = kms
        .database
        .find(Some(&filter), None, user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    results
        .into_iter()
        .next()
        .map(|(uid, _, _)| uid)
        .ok_or_else(|| {
            SpireApiError::InternalError(format!(
                "PKI CA private key with tag '{label}' not found in KMS. \
                 Create a key pair and tag it with '{label}' first."
            ))
        })
}

// ── Route handler ─────────────────────────────────────────────────────────────

/// `POST/PUT /root/sign-intermediate` — sign a CSR with the configured CA key.
///
/// Both methods accepted: the Vault Go SDK uses PUT (via `Logical().Write()`);
/// direct clients may use POST. Body parsing is Content-Type-agnostic.
///
/// The CA key is identified by `vault_pki_ca_key_label` in server config.
/// Returns the signed certificate PEM in a Vault-compatible response.
///
/// Rejects requests with an empty `uri_sans` list (SPIFFE ID is required).
#[allow(clippy::large_futures)]
#[route("/root/sign-intermediate", method = "POST", method = "PUT")]
pub(crate) async fn sign_intermediate(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Bytes,
) -> SpireResult<Json<SignIntermediateResponse>> {
    let user = kms.get_user(&req);
    let body: SignIntermediateRequest = serde_json::from_slice(&body)
        .map_err(|e| SpireApiError::BadRequest(format!("invalid sign-intermediate body: {e}")))?;

    trace!(user = user, "POST/PUT vault pki root/sign-intermediate");

    // Reject if uri_sans is empty — SPIFFE identity is mandatory.
    if body.uri_sans.is_empty() {
        return Err(SpireApiError::BadRequest(
            "uri_sans must not be empty — a SPIFFE ID URI SAN is required".to_owned(),
        ));
    }

    let ca_label = &kms.params.vault_pki_ca_key_label;
    if ca_label.is_empty() {
        return Err(SpireApiError::InternalError(
            "vault_pki_ca_key_label is not configured on this KMS server".to_owned(),
        ));
    }

    // The PKI CA key is a server-level resource created and owned by the server
    // admin (default_username).  AppRole authentication only proves who the caller
    // is; all CA key operations must be performed as the server admin so that any
    // authenticated SPIRE client can trigger certificate signing regardless of which
    // user identity their token maps to.
    let ca_user = kms.params.default_username.clone();

    // Find the CA private key
    let ca_private_key_uid = find_ca_private_key_uid(&kms, ca_label, &ca_user).await?;
    debug!("vault pki: using CA private key uid={ca_private_key_uid}");

    // Build the Certify request
    let csr_pem_bytes = body.csr.as_bytes().to_vec();

    let mut certify_attrs = Attributes::default();
    certify_attrs.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(ca_private_key_uid),
    );

    // Mark the signed certificate as a CA certificate with pathlen:0 so that
    // it can sign SVIDs but not further intermediate CAs.  Without this,
    // OpenSSL's path-validation logic (and SPIRE's own validator) rejects the
    // certificate with "basic constraints are not valid".
    certify_attrs.set_x509_extension_file(
        kms.vendor_id(),
        b"[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,crlSign,digitalSignature\n"
            .to_vec(),
    );

    // G4: forward TTL as requested_validity_days if provided
    if let Some(ttl_str) = &body.ttl {
        if let Some(days) = parse_ttl_days(ttl_str) {
            certify_attrs.set_requested_validity_days(kms.vendor_id(), days);
            debug!(
                "vault pki sign-intermediate: requested_validity_days={days} (from ttl='{ttl_str}')"
            );
        }
    }

    let certify_req = Certify {
        unique_identifier: None,
        certificate_request_type: Some(CertificateRequestType::PEM),
        certificate_request_value: Some(csr_pem_bytes),
        attributes: Some(certify_attrs),
        protection_storage_masks: None,
    };

    let certify_resp = kms
        .certify(certify_req, &ca_user)
        .await
        .map_err(SpireApiError::from)?;

    let cert_uid = certify_resp.unique_identifier.to_string();
    debug!("vault pki: signed intermediate certificate uid={cert_uid}");

    // Retrieve the signed certificate
    let cert_owm = kms
        .database
        .retrieve_object(&cert_uid)
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?
        .ok_or_else(|| {
            SpireApiError::InternalError("signed certificate not found after certify".to_owned())
        })?;

    let signed_cert_x509 = kmip_certificate_to_openssl(cert_owm.object())
        .map_err(|e| SpireApiError::InternalError(format!("certificate conversion failed: {e}")))?;

    let certificate_pem = cert_to_pem(&signed_cert_x509)?;

    // Retrieve the issuing CA certificate (linked to the CA private key's public key)
    // For the beta, we return the signed cert + minimal chain.
    // The issuing_ca is the CA cert linked to the CA private key.
    let issuing_ca_pem = get_issuing_ca_pem(&kms, ca_label, &ca_user).await?;

    // Build ca_chain: [issuing_ca_pem] — root excluded, no duplication of signed cert
    let ca_chain = vec![issuing_ca_pem.clone()];

    Ok(Json(SignIntermediateResponse {
        data: SignIntermediateData {
            certificate: certificate_pem,
            issuing_ca: issuing_ca_pem,
            ca_chain,
        },
    }))
}

/// Retrieve the issuing CA certificate PEM by finding the certificate linked to
/// the CA private key (via its public key's `CertificateLink`).
async fn get_issuing_ca_pem(
    kms: &KMS,
    ca_label: &str,
    user: &str,
) -> Result<String, SpireApiError> {
    // First find the CA private key
    let mut filter = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };
    filter
        .set_tags(kms.vendor_id(), [ca_label])
        .map_err(|e| SpireApiError::InternalError(format!("tag filter error: {e}")))?;

    let results = kms
        .database
        .find(Some(&filter), None, user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    let (ca_sk_uid, _, _) = results.into_iter().next().ok_or_else(|| {
        SpireApiError::InternalError(format!("CA private key with tag '{ca_label}' not found"))
    })?;

    // Retrieve the CA private key to get the public key link
    let ca_sk_owm = kms
        .database
        .retrieve_object(&ca_sk_uid)
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?
        .ok_or_else(|| SpireApiError::InternalError("CA private key not found".to_owned()))?;

    // Follow PublicKeyLink → CertificateLink
    let ca_cert_pem =
        if let Some(pk_link) = ca_sk_owm.attributes().get_link(LinkType::PublicKeyLink) {
            let pk_uid = pk_link.to_string();
            if let Some(pk_owm) = kms
                .database
                .retrieve_object(&pk_uid)
                .await
                .map_err(|e| SpireApiError::InternalError(e.to_string()))?
            {
                if let Some(cert_link) = pk_owm.attributes().get_link(LinkType::CertificateLink) {
                    let cert_uid = cert_link.to_string();
                    if let Some(cert_owm) = kms
                        .database
                        .retrieve_object(&cert_uid)
                        .await
                        .map_err(|e| SpireApiError::InternalError(e.to_string()))?
                    {
                        let x509 = kmip_certificate_to_openssl(cert_owm.object())
                            .map_err(|e| SpireApiError::InternalError(e.to_string()))?;
                        Some(cert_to_pem(&x509)?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    ca_cert_pem.ok_or_else(|| {
        SpireApiError::InternalError(
            "No CA certificate found linked to vault_pki_ca_key_label. \
             Import or certify the CA certificate and link it to the CA key pair."
                .to_owned(),
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde::Deserialize;

    use super::{deserialize_string_or_vec, parse_ttl_days};

    #[test]
    fn parse_ttl_days_handles_all_units() {
        // Hours, rounded up to whole days.
        assert_eq!(parse_ttl_days("8760h"), Some(365));
        assert_eq!(parse_ttl_days("1h"), Some(1));
        assert_eq!(parse_ttl_days("25h"), Some(2));
        // Days pass through unchanged.
        assert_eq!(parse_ttl_days("365d"), Some(365));
        // Seconds, rounded up to whole days.
        assert_eq!(parse_ttl_days("86400s"), Some(1));
        assert_eq!(parse_ttl_days("3600s"), Some(1));
        // Bare integer treated as seconds.
        assert_eq!(parse_ttl_days("86400"), Some(1));
    }

    #[test]
    fn parse_ttl_days_rejects_invalid_input() {
        assert_eq!(parse_ttl_days(""), None);
        assert_eq!(parse_ttl_days("   "), None);
        assert_eq!(parse_ttl_days("abc"), None);
        assert_eq!(parse_ttl_days("12x"), None);
    }

    #[derive(Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "deserialize_string_or_vec")]
        values: Vec<String>,
    }

    #[test]
    fn string_or_vec_accepts_json_array() {
        let h: Holder = serde_json::from_str(r#"{"values": ["a", "b", "c"]}"#).unwrap();
        assert_eq!(h.values, vec!["a", "b", "c"]);
    }

    #[test]
    fn string_or_vec_splits_comma_separated_string() {
        let h: Holder = serde_json::from_str(r#"{"values": "a, b ,c"}"#).unwrap();
        assert_eq!(h.values, vec!["a", "b", "c"]);
    }

    #[test]
    fn string_or_vec_filters_empty_segments() {
        let h: Holder = serde_json::from_str(r#"{"values": "a,,b,"}"#).unwrap();
        assert_eq!(h.values, vec!["a", "b"]);
    }

    #[test]
    fn string_or_vec_defaults_to_empty() {
        let h: Holder = serde_json::from_str("{}").unwrap();
        assert!(h.values.is_empty());
    }
}
