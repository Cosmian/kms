use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS, kmip_types::UniqueIdentifier,
    requests::create_signing_key_pair_request,
};
use cosmian_logger::info;
use serde::{Deserialize, Serialize};

use crate::{
    core::{KMS, ObjectHandle, operations::generate_csr::validate_subject_name},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Body of the CSR generation endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct CsrRequest {
    /// Unique identifier of the private key that signs the CSR (e.g. `hsm::0::subca`).
    /// With `algorithm`, the identifier given to the key pair to create (an `hsm::<slot>::<id>`
    /// identifier creates it in the HSM); generated when absent.
    pub private_key_id: Option<String>,
    /// Subject distinguished name, e.g. `C=FR, O=Acme, CN=Acme Sub CA`.
    pub subject_name: String,
    /// When set, a key pair of this algorithm (`nist-p256`, `rsa4096`, ... as for `Certify`) is
    /// generated first and its private key signs the CSR.
    pub algorithm: Option<String>,
    /// Make the generated private key non-extractable. Mandatory for an HSM key.
    #[serde(default)]
    pub sensitive: bool,
}

/// Response of the CSR generation endpoint.
#[derive(Debug, Serialize)]
pub(crate) struct CsrResponse {
    /// The PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
    /// The private key that signed the CSR.
    pub private_key_id: String,
    /// The public key generated with the private key, when a key pair was generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_id: Option<String>,
}

/// Generate a PKCS#10 CSR signed by a private key held by the KMS or its HSM.
///
/// `POST /certificates/csr`
///
/// # Why authentication is required
///
/// The CSR is signed with the **private key**, which is used as a signing oracle over a
/// caller-chosen subject. The caller needs the `Sign` permission on that key (never `Get`:
/// the key material is never returned, so an HSM key can stay non-extractable). This is a
/// POST so that the subject is not carried in URLs/logs and cannot be triggered by a
/// cross-site navigation carrying the session cookie.
///
/// Returns the PEM-encoded CSR.
#[post("/certificates/csr")]
pub(crate) async fn post_csr(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<CsrRequest>,
) -> KResult<Json<CsrResponse>> {
    let user = kms.get_user(&req);
    info!(
        user = user.as_str(),
        private_key_id = body.private_key_id.as_deref().unwrap_or_default(),
        algorithm = body.algorithm.as_deref().unwrap_or_default(),
        "POST /certificates/csr"
    );
    let (private_key_id, public_key_id) = if let Some(algorithm) = body.algorithm.as_deref() {
        // Checked before the creation: a refused request must leave no key behind.
        if (algorithm.starts_with("ml-dsa") || algorithm.starts_with("slh-dsa"))
            && body
                .private_key_id
                .as_deref()
                .is_some_and(|id| ObjectHandle::from(id).is_hsm())
        {
            kms_bail!(KmsError::InvalidRequest(format!(
                "CSR generation: the HSM cannot generate {algorithm} key pairs; choose an RSA or elliptic-curve algorithm"
            )));
        }
        validate_subject_name(&body.subject_name)?;
        // Checked before the creation so that a refused request leaves no key behind.
        if body
            .private_key_id
            .as_deref()
            .is_some_and(|id| ObjectHandle::from(id).is_hsm())
            && !body.sensitive
        {
            kms_bail!(KmsError::InvalidRequest(
                "CSR generation: a key pair generated in the HSM must be sensitive (non-extractable)"
                    .to_owned()
            ));
        }
        let create = create_signing_key_pair_request(
            kms.vendor_id(),
            algorithm,
            body.private_key_id
                .clone()
                .map(UniqueIdentifier::TextString),
            EMPTY_TAGS,
            body.sensitive,
        )
        .map_err(|e| KmsError::InvalidRequest(format!("CSR generation: {e}")))?;
        let created = Box::pin(kms.create_key_pair(create, &user)).await?;
        (
            created.private_key_unique_identifier.to_string(),
            Some(created.public_key_unique_identifier.to_string()),
        )
    } else {
        if body.sensitive {
            kms_bail!(KmsError::InvalidRequest(
                "CSR generation: `sensitive` only applies to a generated key pair".to_owned()
            ));
        }
        let private_key_id = body.private_key_id.clone().ok_or_else(|| {
            KmsError::InvalidRequest(
                "CSR generation: either private_key_id or algorithm is required".to_owned(),
            )
        })?;
        (private_key_id, None)
    };
    let csr = Box::pin(crate::core::operations::generate_csr::generate_csr(
        &kms,
        &private_key_id,
        &body.subject_name,
        &user,
    ))
    .await?;
    let pem = csr
        .to_pem()
        .map_err(|e| KmsError::ServerError(format!("Failed to encode CSR as PEM: {e}")))?;
    let csr_pem = String::from_utf8(pem)
        .map_err(|e| KmsError::ServerError(format!("Failed to encode CSR as PEM: {e}")))?;
    Ok(Json(CsrResponse {
        csr_pem,
        private_key_id,
        public_key_id,
    }))
}
