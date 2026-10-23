use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_logger::info;
use serde::{Deserialize, Serialize};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Body of the CSR generation endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct CsrRequest {
    /// Unique identifier of the private key that signs the CSR (e.g. `hsm::0::subca`).
    pub private_key_id: String,
    /// Subject distinguished name, e.g. `C=FR, O=Acme, CN=Acme Sub CA`.
    pub subject_name: String,
}

/// Response of the CSR generation endpoint.
#[derive(Debug, Serialize)]
pub(crate) struct CsrResponse {
    /// The PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
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
        private_key_id = body.private_key_id.as_str(),
        "POST /certificates/csr"
    );
    let csr = Box::pin(crate::core::operations::generate_csr::generate_csr(
        &kms,
        &body.private_key_id,
        &body.subject_name,
        &user,
    ))
    .await?;
    let pem = csr
        .to_pem()
        .map_err(|e| KmsError::ServerError(format!("Failed to encode CSR as PEM: {e}")))?;
    let csr_pem = String::from_utf8(pem)
        .map_err(|e| KmsError::ServerError(format!("Failed to encode CSR as PEM: {e}")))?;
    Ok(Json(CsrResponse { csr_pem }))
}
