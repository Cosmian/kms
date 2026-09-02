use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_objects::{Certificate, Object},
    kmip_operations::{Validate, ValidateResponse},
    kmip_types::{UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::{debug, trace, warn};
use openssl::{
    asn1::Asn1Time,
    stack::Stack,
    x509::{
        CrlStatus, DistPointNameRef, DistPointRef, GeneralNameRef, X509, X509Crl, X509StoreContext,
        store::X509StoreBuilder,
    },
};

use crate::{
    config::ProxyParams,
    core::{
        KMS, certificate::validate_crl_url, operations::certify::rfc9608,
        retrieve_object_utils::retrieve_object_for_operation, uid_utils::ObjectHandle,
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

static CRL_CACHE_MAP: LazyLock<tokio::sync::RwLock<HashMap<String, Vec<u8>>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// This operation requests the server to validate a certificate chain and return
/// information on its validity.
///
/// Only a single certificate chain SHALL be included in each request.
/// The request MAY contain a list of certificate objects, and/or a list of
/// Unique Identifiers that identify Managed Certificate objects.
///
/// Together, the two lists compose a certificate chain to be validated.
///
/// The request MAY also contain a date for which all certificates in the
/// certificate chain are REQUIRED to be valid.
///
/// The method or policy by which validation is conducted is a decision of the
/// server and is outside of the scope of this protocol. Likewise, the order in
/// which the supplied certificate chain is validated and the specification of
/// trust anchors used to terminate validation are also controlled by the server.
///
/// # Arguments
///
/// * `kms` - A reference to the KMS (Key Management Service) instance.
/// * `request` - The `Validate` request containing the unique identifier and/or certificates to be validated.
/// * `user` - A `UserId` representing the user requesting the validation.
/// * `params` - An optional reference to additional database parameters.
///
/// # Returns
///
/// A `KResult` containing a `ValidateResponse` which indicates the validity of the certificates.
///
/// # Errors
///
/// This function will return a `KmsError` if:
/// - The number of certificates found in the database does not match the number of certificates in the request.
/// - There is an error converting the certificates from bytes to X509 format.
/// - There is an error sorting the certificates.
/// - There is an error verifying the chain signature.
/// - There is an error validating the chain date.
/// - There is an error verifying the CRLs (Certificate Revocation Lists).
pub(crate) async fn validate_operation(
    kms: &KMS,
    request: Validate,
    user: &UserId,
) -> KResult<ValidateResponse> {
    trace!("Validate: {}", request);

    debug!("Get input certificates as bytes");
    let (certificates, certificates_number) = match (request.unique_identifier, request.certificate)
    {
        (None, None) => {
            return Err(KmsError::Certificate(
                "Empty chain cannot be validated".to_owned(),
            ));
        }
        (None, Some(certificates)) => Ok::<_, KmsError>((certificates.clone(), certificates.len())),
        (Some(mut unique_identifiers), None) => {
            let set: HashSet<_> = unique_identifiers.drain(..).collect(); // dedup
            unique_identifiers.extend(set);
            Ok((
                Box::pin(certificates_by_uid(unique_identifiers.clone(), kms, user)).await?,
                unique_identifiers.len(),
            ))
        }
        (Some(mut unique_identifiers), Some(certificates)) => {
            let set: HashSet<_> = unique_identifiers.drain(..).collect(); // dedup
            unique_identifiers.extend(set);
            Ok((
                [
                    certificates.clone(),
                    Box::pin(certificates_by_uid(unique_identifiers.clone(), kms, user)).await?,
                ]
                .concat(),
                certificates.len() + unique_identifiers.len(),
            ))
        }
    }?;

    debug!("Number of certificates in chain: {certificates_number}");
    if certificates.len() != certificates_number {
        return Err(KmsError::Certificate(
            "Number of certificates found in database and number of certificates in request do \
             not match"
                .to_owned(),
        ));
    }

    // Convert the certificates from bytes to X509
    let certificates = certificates
        .into_iter()
        .map(|cert| X509::from_der(cert.as_slice()))
        .collect::<Result<Vec<X509>, _>>()?;

    // Sort the chain in right order: ROOT/SUBCA/../LEAF.
    // Sorting the chain greatly simplify the flow in the signature and revocation verification
    let certificates = if certificates.len() > 1 {
        sort_certificates(&certificates)?
    } else {
        certificates
    };

    verify_chain_signature(&certificates)?;
    validate_chain_date(&certificates, &request.validity_time)?;

    // CRL check: hard CRL errors (expired CRL, bad signature, explicit revocation)
    // make the chain invalid. Network errors (unreachable CRL distribution point)
    // are treated as soft failures inside `verify_crls()` and do not cause
    // this function to return an error — the certificate is treated as valid when
    // the CRL DP is simply unreachable. Only deterministic revocation evidence
    // or a malformed/expired CRL propagates here as an error.
    if let Err(crl_err) = verify_crls(
        certificates,
        kms.params.proxy_params.as_ref(),
        kms.params.kms_public_url.as_deref(),
    )
    .await
    {
        warn!("CRL validation failed: {crl_err}");
        return Err(KmsError::Certificate(format!(
            "Certificate chain is invalid: {crl_err}"
        )));
    }

    Ok(ValidateResponse {
        validity_indicator: ValidityIndicator::Valid,
    })
}

/// Extracts the subject key identifier and authority key identifier from an X509 certificate.
///
/// # Arguments
///
/// * `certificate` - A reference to an `X509` certificate from which the identifiers will be extracted.
///
/// # Returns
///
/// A tuple containing two byte slices:
///
/// * The first element is the subject key identifier as a byte slice.
/// * The second element is the authority key identifier as a byte slice.
///
/// If either identifier is not present in the certificate, an empty byte slice is returned for that identifier.
fn get_certificate_identifiers(certificate: &X509) -> (&[u8], &[u8]) {
    (
        certificate
            .subject_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default(),
        certificate
            .authority_key_id()
            .map(openssl::asn1::Asn1OctetStringRef::as_slice)
            .unwrap_or_default(),
    )
}

/// Debug the details of a given X.509 certificate along with a debug message.
///
/// This function retrieves the Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
/// from the provided certificate and logs them along with the certificate's subject name and
/// a custom debug message.
///
/// # Arguments
///
/// * `debug_msg` - A string slice that holds the debug message to be logged.
/// * `certificate` - A reference to an `X509` certificate whose details are to be traced.
///
/// # Panics
///
/// This function does not panic.
///
/// # Errors
///
/// This function does not return errors.
fn trace_certificate(debug_msg: &str, certificate: &X509) {
    let (ski, aki) = get_certificate_identifiers(certificate);
    trace!(
        "{debug_msg}. Certificate: subject: {:?}, AKI: {:?}, SKI: {:?}",
        certificate.subject_name(),
        hex::encode(ski),
        hex::encode(aki),
    );
}

/// Sort a X509 certificate list according to their Authority Key Identifier (AKI) and Subject Key Identifier (SKI).
/// AKI and SKI MUST appear as CA certificate X509 extensions.
///
/// Order of output chain will be ROOT/SUBCA/../LEAF.
///
/// As a reminder: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>:
///
/// To facilitate certification path construction, this extension MUST
/// appear in all conforming CA certificates, that is, all certificates
/// including the basic constraints extension (Section 4.2.1.9) where the
/// value of cA is TRUE.  In conforming CA certificates, the value of the
/// subject key identifier MUST be the value placed in the key identifier
/// field of the authority key identifier extension (Section 4.2.1.1) of
/// certificates issued by the subject of this certificate.  Applications
/// are not required to verify that key identifiers match when performing
/// certification path validation.
///
/// Only leaf certificates can omit AKI and SKI.
///
/// # Arguments
///
/// * `certificates` - The list of X509 certificates to sort.
///
/// # Returns
///
/// Returns a `Result` containing the sorted list of X509 certificates if successful,
/// or a `KmsError` if an error occurs during the sorting process.
fn sort_certificates(certificates: &[X509]) -> KResult<Vec<X509>> {
    let mut sorted_chains = Vec::<X509>::with_capacity(certificates.len());
    let mut certificates_copy: Vec<X509> = certificates.to_vec();
    let mut indexes_to_remove = vec![];

    // First step, identify root and leaf.
    // Certificates are identified by their Subject Key Identifier (SKI) and
    // Authority Key Identifier (AKI):
    //
    //   Root (self-signed) — two detection strategies:
    //     1. Explicit:    SKI == AKI && !SKI.is_empty()  (classical PKI with AKI set)
    //     2. Self-signed: issuer_name == subject_name    (RFC 5280 §4.2.1.1 allows
    //        AKI to be omitted for self-signed certs; required for PQC root CAs
    //        generated in-process where no issuer cert is available in the OpenSSL
    //        X.509 builder context when the AKI extension would be set).
    //
    //   Leaf (no extensions at all): AKI.is_empty() && SKI.is_empty()
    for (index, certificate) in certificates_copy.iter().enumerate() {
        let (ski, aki) = get_certificate_identifiers(certificate);
        trace_certificate("Finding root (or leaf)", certificate);

        // Root detection #1: explicit AKI == SKI (classical PKI behaviour).
        let is_root_explicit = ski == aki && !ski.is_empty();
        // Root detection #2: self-signed certificate (issuer == subject).
        // RFC 5280 §4.2.1.1: AKI MAY be omitted for self-signed certificates.
        let is_root_self_signed = certificate
            .subject_name()
            .to_der()
            .ok()
            .zip(certificate.issuer_name().to_der().ok())
            .is_some_and(|(subj, iss)| !subj.is_empty() && subj == iss);

        if is_root_explicit || is_root_self_signed {
            trace_certificate("Root found", certificate);
            if !sorted_chains.contains(certificate) {
                sorted_chains.insert(0, certificate.to_owned());
            }
            indexes_to_remove.push(index);
        } else if aki.is_empty() && ski.is_empty() {
            trace_certificate("No AKI nor SKI -> leaf found", certificate);
            if !sorted_chains.contains(certificate) {
                sorted_chains.push(certificate.to_owned());
            }
            indexes_to_remove.push(index);
        }
    }

    if sorted_chains.is_empty() {
        return Err(KmsError::Certificate(
            "No root authority found, cannot proceed full chain validation".to_owned(),
        ));
    }

    for &index in indexes_to_remove.iter().rev() {
        certificates_copy.remove(index);
    }

    trace!(
        "Root and possibly leaf removed from initial certificate list. Left: {}",
        certificates_copy.len()
    );
    // since certificates are not in the right order, we need to loop on the number of certificates - worst case
    for _ in 0..certificates.len() {
        if sorted_chains.len() == certificates.len() {
            trace!("All certificates have been sorted");
            break;
        }
        for certificate in &certificates_copy {
            if sorted_chains.len() == certificates.len() {
                trace!("All certificates have been sorted");
                break;
            }
            let (ski, aki) = get_certificate_identifiers(certificate);
            trace_certificate(
                "Trying to find the certificate position on the sorted list",
                certificate,
            );

            for (idx, sorted_certificate) in sorted_chains.clone().iter().enumerate() {
                let (ski_2, aki_2) = get_certificate_identifiers(sorted_certificate);
                trace_certificate("Iterate on sorted certificates", sorted_certificate);

                // Found a certificate child
                if aki == ski_2 && !aki.is_empty() && !sorted_chains.contains(certificate) {
                    trace_certificate(
                        &format!("Insert certificate at index: {}", idx + 1),
                        certificate,
                    );
                    sorted_chains.insert(idx + 1, certificate.to_owned());
                    break;
                }

                // Found the authority of the certificate
                if ski == aki_2 && !ski.is_empty() && !sorted_chains.contains(certificate) {
                    trace_certificate(&format!("Insert certificate at index: {idx}"), certificate);
                    sorted_chains.insert(idx, certificate.to_owned());
                    break;
                }

                // Not yet placeable: this sorted_certificate is not the right neighbour.
                // Try the next sorted candidate in the inner loop before giving up.
                trace!(
                    "Sorted candidate mismatch: cert AKI={}, SKI={}, sorted SKI={}, AKI={}",
                    hex::encode(aki),
                    hex::encode(ski),
                    hex::encode(ski_2),
                    hex::encode(aki_2)
                );
            }
        }
    }

    if sorted_chains.len() != certificates.len() {
        return Err(KmsError::Certificate(
            "Failed to sort the certificates. Certificate chain incomplete?".to_owned(),
        ));
    }

    Ok(sorted_chains)
}

/// Verifies the signature of a chain of X509 certificates.
///
/// # Arguments
///
/// * `certificates` - A slice of X509 certificates representing the certificate chain.
///
/// # Returns
///
/// * `KResult<ValidityIndicator>` - Returns `Ok(ValidityIndicator::Valid)` if the certificate chain is valid,
///   otherwise returns an error of type `KmsError::Certificate`.
///
/// # Errors
///
/// This function will return an error in the following cases:
///
/// * If the certificate chain is empty.
/// * If there is an issue creating the X509 store builder.
/// * If there is an issue adding certificates to the store.
/// * If there is an issue building the store.
/// * If there is an issue creating the store context for verification.
/// * If the verification of the certificate chain fails.
/// * If the verification of individual certificates in the chain fails.
fn verify_chain_signature(certificates: &[X509]) -> KResult<ValidityIndicator> {
    trace!(
        "verify_chain_signature: entering: number of certificates: {}",
        certificates.len()
    );
    if certificates.is_empty() {
        return Err(KmsError::Certificate(
            "Certificate chain is empty".to_owned(),
        ));
    }

    // Create a new X509 store builder
    let mut builder = X509StoreBuilder::new()?;

    // Get leaf
    let leaf = certificates.last().ok_or_else(|| {
        KmsError::Certificate("Failed to get last element of the chain".to_owned())
    })?;

    // Add authorities to the store
    if certificates.len() == 1 {
        builder.add_cert(leaf.to_owned())?;
    } else {
        for certificate in certificates.iter().take(certificates.len() - 1) {
            builder.add_cert(certificate.to_owned())?;
        }
    }

    // Build the store
    let store = builder.build();

    // Create a store context for verification
    let mut context = X509StoreContext::new()?;
    let result = context.init(
        &store,
        leaf,
        Stack::new()?.as_ref(),
        openssl::x509::X509StoreContextRef::verify_cert,
    )?;

    if !result {
        // Get the last error message from the context
        return Err(KmsError::Certificate(format!(
            "Result of the function verify_cert: {result:?}. Error message: {}",
            context.error()
        )));
    }

    // verify signatures in cascade
    let mut issuer_public_key = certificates
        .first()
        .ok_or_else(|| {
            KmsError::Certificate("Failed to get the first element of the chain".to_owned())
        })?
        .public_key()?;
    for cert in certificates {
        if !cert.verify(&issuer_public_key)? {
            return Err(KmsError::Certificate(format!(
                "Failed to verify the certificate: {:?}",
                cert.subject_name()
            )));
        }
        issuer_public_key = cert.public_key()?;
    }

    Ok(ValidityIndicator::Valid)
}

/// Maximum CRL body size accepted from a remote server (10 MiB).
///
/// Prevents unbounded memory allocation via a slow or large HTTP response.
/// Real-world CRLs are typically a few kilobytes to a few megabytes.
const CRL_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Retrieves Certificate Revocation List (CRL) bytes from a list of URIs.
///
/// In production, only `http://` and `https://` URIs are fetched. All other URI
/// types (bare filesystem paths, LDAP, FTP, …) are rejected to prevent
/// Server-Side Request Forgery (COSMIAN-2026-020).
///
/// When the `insecure` feature is enabled (or in `#[cfg(test)]` builds),
/// `file://` URIs are additionally permitted so that integration tests and
/// air-gapped test environments can load local CRL fixtures without an HTTP
/// server. **Never enable the `insecure` feature in production.**
///
/// URLs that begin with `kms_public_url` (the server's own base URL) are
/// exempted from the SSRF host check: the KMS server may legitimately fetch
/// its own auto-generated CRL endpoint.
///
/// Each HTTP(S) URL is validated against [`validate_crl_url`] before any
/// network I/O: private/loopback/link-local IP ranges and internal hostnames
/// are rejected unless covered by the `kms_public_url` exemption above.
/// HTTP redirects are never followed. Responses are capped at
/// [`CRL_MAX_RESPONSE_BYTES`] and the request times out after 30 seconds.
///
/// Successfully fetched CRLs are cached in [`CRL_CACHE_MAP`] to avoid
/// redundant network round-trips within the same server process.
///
/// # Errors
///
/// Returns [`KmsError::Certificate`] if:
/// - A URI uses a non-HTTP(S) scheme or is a bare filesystem path (production).
/// - The URL targets a private, loopback, link-local, or internal hostname
///   (and is not the server's own URL).
/// - The HTTP request fails, times out, or returns a non-2xx status.
/// - The response body exceeds [`CRL_MAX_RESPONSE_BYTES`].
async fn get_crl_bytes(
    uri_list: Vec<String>,
    proxy_params: Option<&ProxyParams>,
    kms_public_url: Option<&str>,
) -> KResult<HashMap<String, Vec<u8>>> {
    trace!("get_crl_bytes: entering: uri_list: {uri_list:?}");

    let mut result = HashMap::new();

    for uri in uri_list {
        // SECURITY (COSMIAN-2026-020): when the `insecure` feature is enabled (or
        // in unit-test builds), `file://` URIs are resolved locally so that test
        // environments can load CRL fixtures without an HTTP server.
        // In standard production builds this branch is compiled out entirely.
        #[cfg(any(test, feature = "insecure"))]
        if uri.starts_with("file://") {
            let parsed = url::Url::parse(&uri).map_err(|e| {
                KmsError::Certificate(format!("Invalid file:// CRL URI '{uri}': {e}"))
            })?;
            let path_buf = parsed.to_file_path().map_err(|()| {
                KmsError::Certificate(format!("Cannot convert file:// URI to path: {uri}"))
            })?;
            let crl_bytes = std::fs::read(&path_buf).map_err(|e| {
                KmsError::Certificate(format!(
                    "Failed to read CRL from file '{}': {e}",
                    path_buf.display()
                ))
            })?;
            result.insert(uri, crl_bytes);
            continue;
        }

        // SECURITY (COSMIAN-2026-020): reject every non-HTTP(S) URI in production.
        // This covers bare filesystem paths, file:// (production), LDAP, FTP, etc.
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            if let Ok(parsed) = url::Url::parse(&uri) {
                return Err(KmsError::Certificate(format!(
                    "CRL Distribution Point URI scheme '{}' is not permitted; \
                     only http and https are accepted",
                    parsed.scheme()
                )));
            }
            // Bare filesystem path (not a valid URL at all).
            return Err(KmsError::Certificate(format!(
                "CRL Distribution Point value '{uri}' is not a valid URL; \
                 filesystem paths are not accepted"
            )));
        }

        // SECURITY (COSMIAN-2026-020): validate the URL against SSRF targets
        // (private IPs, loopback, link-local, internal hostnames) before any
        // network I/O.
        // Exemption: URLs that begin with the server's own public URL are trusted —
        // the KMS may legitimately fetch its own auto-generated CRL endpoint
        // (`/public/certificates/{id}/crl`), which may resolve to localhost in
        // development and test environments.
        let is_own_url = kms_public_url.is_some_and(|base| uri.starts_with(base));
        if !is_own_url {
            validate_crl_url(&uri)?;
        }

        let mut crls = CRL_CACHE_MAP.write().await;
        if crls.contains_key(&uri) {
            debug!("CRL cache hit: {uri}");
            crls.get(&uri).and_then(|v| result.insert(uri, v.clone()));
            continue;
        }

        let mut client_builder = reqwest::Client::builder()
            // SECURITY (COSMIAN-2026-020): never follow redirects — a 3xx to an
            // internal address would bypass the URL validation above.
            .redirect(reqwest::redirect::Policy::none())
            // Bound the total request time to prevent slowloris / resource exhaustion.
            .timeout(std::time::Duration::from_secs(30));

        if let Some(proxy_params) = proxy_params {
            let mut proxy = reqwest::Proxy::all(proxy_params.url.clone()).map_err(|e| {
                KmsError::Certificate(format!(
                    "Failed to configure the HTTPS proxy for CRL fetch: {e}"
                ))
            })?;
            if let Some(ref username) = proxy_params.basic_auth_username {
                proxy = proxy.basic_auth(
                    username,
                    proxy_params
                        .basic_auth_password
                        .as_deref()
                        .unwrap_or_default(),
                );
            } else if let Some(ref custom_auth_header) = proxy_params.custom_auth_header {
                proxy = proxy.custom_http_auth(
                    reqwest::header::HeaderValue::from_str(custom_auth_header).map_err(|e| {
                        KmsError::Certificate(format!(
                            "Failed to set custom HTTP auth header for CRL fetch: {e}"
                        ))
                    })?,
                );
            }
            if !proxy_params.exclusion_list.is_empty() {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
                    &proxy_params.exclusion_list.join(","),
                ));
            }
            client_builder = client_builder.proxy(proxy);
        }

        let response = client_builder
            .build()
            .map_err(|e| {
                KmsError::Certificate(format!("Failed to build reqwest client for CRL fetch: {e}"))
            })?
            .get(&uri)
            .send()
            // IMPORTANT: use `?` (not `.map_err`) so that `From<reqwest::Error>`
            // converts network errors to `KmsError::ClientConnectionError`.
            // `verify_crls()` treats `ClientConnectionError` as a soft failure
            // (unreachable CRL DP) and `Certificate` as a hard failure.
            .await?;

        debug!(
            "CRL response received: uri={uri} status={}",
            response.status()
        );

        if !response.status().is_success() {
            return Err(KmsError::Certificate(format!(
                "CRL at '{uri}' returned non-success status: {}",
                response.status()
            )));
        }

        // SECURITY (COSMIAN-2026-020): cap the body size to prevent memory
        // exhaustion from an unbounded response.bytes().await call.
        // Use saturating conversion: on 32-bit targets a u64 > usize::MAX
        // would overflow; we treat that as "exceeds limit" which is correct.
        let content_length =
            usize::try_from(response.content_length().unwrap_or(0)).unwrap_or(usize::MAX);
        if content_length > CRL_MAX_RESPONSE_BYTES {
            return Err(KmsError::Certificate(format!(
                "CRL at '{uri}' reports Content-Length {content_length} which exceeds the \
                 {CRL_MAX_RESPONSE_BYTES}-byte limit"
            )));
        }

        let crl_bytes = response.bytes().await.map_err(|e| {
            KmsError::Certificate(format!("Error reading CRL body from '{uri}': {e}"))
        })?;

        if crl_bytes.len() > CRL_MAX_RESPONSE_BYTES {
            return Err(KmsError::Certificate(format!(
                "CRL body from '{uri}' is {} bytes, exceeding the {CRL_MAX_RESPONSE_BYTES}-byte \
                 limit",
                crl_bytes.len()
            )));
        }

        let crl_bytes = crl_bytes.to_vec();
        debug!("CRL fetched: uri={uri} size={}", crl_bytes.len());
        crls.insert(uri.clone(), crl_bytes.clone());
        result.insert(uri, crl_bytes);
    }

    debug!(
        "get_crl_bytes: exiting in success with {} CRLs",
        result.len()
    );
    Ok(result)
}

/// Verifies the Certificate Revocation Lists (CRLs) for a given list of certificates.
///
/// This function iterates over the provided certificates and performs the following checks:
/// 1. For each certificate, if it is not the first one, it checks if the certificate is present in the parent CRLs.
/// 2. If the certificate has CRL distribution points, it fetches the CRLs from the specified URIs and verifies them.
///
/// # Arguments
///
/// * `certificates` - A vector of `X509` certificates to be verified.
///
/// # Returns
///
/// * `KResult<ValidityIndicator>` - Returns `ValidityIndicator::Valid` if all certificates are valid,
///   otherwise returns an error indicating the reason for invalidity.
///
/// # Errors
///
/// This function will return an error in the following cases:
/// * If a certificate is found to be revoked or removed from the CRL.
/// * If there is an issue deserializing a CRL.
/// * If the CRL signature is invalid.
/// * If there is an issue fetching the CRL bytes from the URIs.
pub(crate) async fn verify_crls(
    certificates: Vec<X509>,
    proxy_params: Option<&ProxyParams>,
    kms_public_url: Option<&str>,
) -> KResult<ValidityIndicator> {
    let mut current_crls: HashMap<String, Vec<u8>> = HashMap::new();

    for (idx, certificate) in certificates.iter().enumerate() {
        debug!(
            "[{idx}] Verifying certificate: subject: {:?}",
            certificate.subject_name()
        );

        // Test if certificate is in parent CRLs
        //
        if idx > 0 {
            for (crl_path, crl_value) in &current_crls {
                let crl = X509Crl::from_pem(crl_value.as_slice())
                    .or_else(|_| X509Crl::from_der(crl_value.as_slice()))?;
                trace!("CRL deserialized OK: {crl_path}");

                // RFC 5280 §6.3 step (a)(1)(ii): reject expired CRLs.
                check_crl_freshness(&crl, crl_path)?;

                let res = crl_status_to_validity_indicator(&crl.get_by_cert(certificate));
                debug!("Parent CRL verification: revocation status: {res:?}");
                if res == ValidityIndicator::Invalid {
                    return Err(KmsError::Certificate(
                        "Certificate is revoked or removed from CRL".to_owned(),
                    ));
                }
            }
        }
        // RFC 9608 §4: skip CRL checks for certificates that carry id-ce-noRevAvail.
        // The extension signals that no revocation information is available; a
        // relying party MUST NOT reject the certificate for lack of a CRL/OCSP response.
        if rfc9608::has_extension(certificate) {
            debug!("[{idx}] Certificate carries id-ce-noRevAvail (RFC 9608): skipping CRL check");
            continue;
        }

        if let Some(crl_dp) = certificate.crl_distribution_points() {
            let crl_size = crl_dp.len();
            let mut uri_list = Vec::with_capacity(crl_size);
            for i in 0..crl_size {
                if let Some(fullname) = crl_dp
                    .get(i)
                    .and_then(DistPointRef::distpoint)
                    .and_then(DistPointNameRef::fullname)
                {
                    for j in 0..fullname.len() {
                        if let Some(crl_uri) = fullname.get(j).and_then(GeneralNameRef::uri) {
                            if !uri_list.contains(&crl_uri.to_owned()) {
                                uri_list.push(crl_uri.to_owned());
                                trace!("Found CRL URI: {crl_uri}");
                            }
                        }
                    }
                }
            }

            // RFC 5280 §6.3: if the CRL distribution point is unreachable
            // (network error, DNS failure), the revocation status cannot be
            // determined.  Treat this as a soft failure — warn and skip the
            // revocation check for this certificate.  Hard errors (expired CRL,
            // bad signature, explicit revocation) still propagate.
            match get_crl_bytes(uri_list, proxy_params, kms_public_url).await {
                Ok(crls) => {
                    current_crls = crls;
                }
                Err(KmsError::ClientConnectionError(ref e)) => {
                    warn!(
                        "[{idx}] CRL distribution point unreachable for '{:?}', skipping \
                         revocation check: {e}",
                        certificate.subject_name()
                    );
                    current_crls = HashMap::new();
                    continue;
                }
                Err(e) => return Err(e),
            }

            // Test if certificate is in current CRLs
            //
            for (crl_path, crl_value) in &current_crls {
                // Verifying that the CRL is properly signed by its issuer
                let crl = X509Crl::from_pem(crl_value.as_slice())
                    .or_else(|_| X509Crl::from_der(crl_value.as_slice()))?;
                trace!("CRL deserialized OK: {crl_path}");

                // RFC 5280 §6.3 step (a)(1)(ii): reject expired CRLs.
                check_crl_freshness(&crl, crl_path)?;

                // RFC 5280 §6.3 step (f): verify CRL signature.
                //
                // For HTTP(S)-fetched CRLs, an unverifiable signature is a hard error:
                // a MITM could substitute a forged CRL that omits revoked entries.
                //
                // For file:// and filesystem-path CRLs (local, OS-controlled delivery),
                // signature verification failure is a warning only — the file path itself
                // is already trusted at the OS level.
                let crl_issuer = crl.issuer_name();
                let crl_issuer_der = crl_issuer.to_der()?;
                let mut verified = false;
                for cand in certificates.iter().take(idx + 1) {
                    // Propagate DER encoding failures rather than silently skipping
                    // the issuer match (which would leave `verified = false` and reject
                    // a valid CRL as unverified).
                    let cand_subject_der = cand.subject_name().to_der().map_err(|e| {
                        KmsError::Certificate(format!(
                            "Failed to DER-encode candidate subject name for CRL issuer match: {e}"
                        ))
                    })?;
                    if cand_subject_der.as_slice() == crl_issuer_der.as_slice() {
                        let key = cand.public_key()?;
                        if crl.verify(&key)? {
                            verified = true;
                            break;
                        }
                    }
                }
                if !verified {
                    let is_http =
                        crl_path.starts_with("http://") || crl_path.starts_with("https://");
                    if is_http {
                        // Use ServerError (not Certificate) so that import.rs treats this as
                        // a soft infrastructure failure (→ Active) rather than evidence of
                        // revocation (→ Compromised). The Validate operation propagates the
                        // error to the caller regardless of error type.
                        return Err(KmsError::ServerError(format!(
                            "CRL signature verification failed for HTTP CRL '{crl_path}'; \
                             issuer: {crl_issuer:?}. Rejecting to prevent forged-CRL attack."
                        )));
                    }
                    warn!(
                        "CRL signature could not be verified against chain issuers; \
                         issuer: {crl_issuer:?}, path: {crl_path}. \
                         Continuing (trusted local delivery)."
                    );
                }

                let res = crl_status_to_validity_indicator(&crl.get_by_cert(certificate));
                debug!("Revocation status: result: {res:?}");
                if res == ValidityIndicator::Invalid {
                    return Err(KmsError::Certificate(
                        "Certificate is revoked or removed from CRL".to_owned(),
                    ));
                }
            }
        }
    }
    trace!("verify_crls: exiting in success");
    Ok(ValidityIndicator::Valid)
}

// If fetching a certificate fails, the method reports the first error happening.
// Otherwise it returns a vector of certificates.
async fn certificates_by_uid(
    unique_identifiers: Vec<UniqueIdentifier>,
    kms: &KMS,
    user: &UserId,
) -> KResult<Vec<Vec<u8>>> {
    for uid in &unique_identifiers {
        debug!("{} identifiers", uid);
    }
    let mut results = Vec::new();
    for unique_identifier in &unique_identifiers {
        let handle = ObjectHandle::try_from(unique_identifier)?;
        let result = Box::pin(certificate_by_uid(handle, kms, user)).await?;
        results.push(result);
    }
    Ok(results)
}

// Fetches a certificate. If it fails, returns the according error
async fn certificate_by_uid(
    handle: ObjectHandle<'_>,
    kms: &KMS,
    user: &UserId,
) -> KResult<Vec<u8>> {
    let uid_owm = Box::pin(retrieve_object_for_operation(
        handle,
        KmipOperation::Validate,
        kms,
        user,
    ))
    .await?;

    if let Object::Certificate(Certificate {
        certificate_type: _,
        certificate_value,
    }) = uid_owm.object()
    {
        Ok(certificate_value.clone())
    } else {
        Err(KmsError::Certificate(format!(
            "Requested a Certificate Object, got a {}",
            uid_owm.object().object_type()
        )))
    }
}

fn validate_chain_date(certificates: &[X509], date: &Option<String>) -> KResult<ValidityIndicator> {
    let current_date = date.clone().map_or_else(
        || Asn1Time::days_from_now(0),
        |date| Asn1Time::from_str(date.as_str()),
    )?;
    certificates
        .iter()
        .try_fold(ValidityIndicator::Valid, |acc, certificate| {
            let validation = validate_date(certificate, &current_date);
            if validation == ValidityIndicator::Invalid {
                Err(KmsError::Certificate(format!(
                    "According to this date ({date:?}), the following certificate will be invalid \
                     {:?}",
                    certificate.subject_name()
                )))
            } else {
                Ok(acc.and(validation))
            }
        })
}

fn validate_date(certificate: &X509, date: &Asn1Time) -> ValidityIndicator {
    let now = date.as_ref();
    let (start, stop) = (certificate.not_before(), certificate.not_after());
    if start <= now && now <= stop {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    }
}

const fn crl_status_to_validity_indicator(status: &CrlStatus) -> ValidityIndicator {
    match status {
        CrlStatus::NotRevoked => ValidityIndicator::Valid,
        CrlStatus::RemoveFromCrl(_) | CrlStatus::Revoked(_) => ValidityIndicator::Invalid,
    }
}

/// Check that a CRL has not passed its `nextUpdate` time (RFC 5280 §6.3 step (a)(1)(ii)).
///
/// Returns an error if the CRL is expired. A CRL whose `nextUpdate` field is absent
/// (non-conformant) is treated as expired per the RFC 5280 MUST requirement.
fn check_crl_freshness(crl: &X509Crl, crl_path: &str) -> KResult<()> {
    let now = Asn1Time::days_from_now(0).map_err(|e| {
        // Use ServerError (not Certificate) so that `import.rs` treats this as
        // a soft infrastructure failure rather than as evidence of revocation.
        KmsError::ServerError(format!(
            "Failed to get current time for CRL freshness check: {e}"
        ))
    })?;

    let next_update = crl.next_update().ok_or_else(|| {
        // Missing nextUpdate — RFC 5280 §5.1.2.5 requires the field; treat as
        // infrastructure problem, not a revocation signal.
        KmsError::ServerError(format!(
            "CRL '{crl_path}' has no nextUpdate field; treating as expired (RFC 5280 §6.3)"
        ))
    })?;

    // `next_update < now` → the CRL is past its validity period.
    // Return ServerError (not Certificate) so that import.rs treats this as
    // "CRL infrastructure unavailable / stale" (soft fail → keep Active state)
    // rather than "certificate is revoked" (hard fail → Compromised state).
    // The Validate operation returns the error to the caller regardless of type.
    if next_update < now {
        return Err(KmsError::ServerError(format!(
            "CRL '{crl_path}' is expired (nextUpdate is in the past). \
             Regenerate the CRL and retry validation (RFC 5280 §6.3)."
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::core::certificate::validate_crl_url;

    // ── validate_crl_url unit tests ─────────────────────────────────────────────

    /// SR-CRL-01: loopback IPv4 addresses must be rejected (COSMIAN-2026-020).
    #[test]
    fn sr_crl_01_loopback_ipv4_blocked() {
        let err = validate_crl_url("http://127.0.0.1:8765/crl").unwrap_err();
        assert!(
            err.to_string().contains("loopback") || err.to_string().contains("private"),
            "Expected loopback/private error, got: {err}"
        );
    }

    /// SR-CRL-02: private RFC-1918 IPv4 addresses must be rejected.
    #[test]
    fn sr_crl_02_private_ipv4_blocked() {
        for url in &[
            "http://10.0.0.1/crl",
            "http://172.16.0.1/crl",
            "http://192.168.1.1/crl",
        ] {
            let err = validate_crl_url(url).unwrap_err();
            assert!(
                err.to_string().contains("private") || err.to_string().contains("loopback"),
                "Expected private-IP error for {url}, got: {err}"
            );
        }
    }

    /// SR-CRL-03: cloud metadata IP (169.254.169.254) must be rejected as link-local.
    #[test]
    fn sr_crl_03_link_local_metadata_ip_blocked() {
        let err = validate_crl_url("http://169.254.169.254/latest/meta-data/").unwrap_err();
        assert!(
            err.to_string().contains("link-local")
                || err.to_string().contains("loopback")
                || err.to_string().contains("private"),
            "Expected link-local/private error, got: {err}"
        );
    }

    /// SR-CRL-04: well-known internal hostnames must be rejected.
    #[test]
    fn sr_crl_04_internal_hostnames_blocked() {
        for url in &[
            "http://localhost/crl",
            "http://metadata.google.internal/crl",
            "http://kms.svc.cluster.local/crl",
            "http://vault.internal/crl",
        ] {
            let err = validate_crl_url(url).unwrap_err();
            assert!(
                err.to_string().contains("internal"),
                "Expected internal-hostname error for {url}, got: {err}"
            );
        }
    }

    /// SR-CRL-05: non-HTTP(S) schemes must be rejected.
    #[test]
    fn sr_crl_05_non_http_scheme_blocked() {
        for url in &[
            "ftp://crl.example.com/crl.der",
            "ldap://crl.example.com/crl",
        ] {
            let err = validate_crl_url(url).unwrap_err();
            assert!(
                err.to_string().contains("scheme"),
                "Expected scheme error for {url}, got: {err}"
            );
        }
    }

    /// SR-CRL-06: public HTTP and HTTPS URLs must pass validation.
    #[test]
    fn sr_crl_06_public_urls_allowed() {
        for url in &[
            "http://crl.example.com/crl.der",
            "https://pki.example.com/crl/intermediate.crl",
        ] {
            validate_crl_url(url).unwrap_or_else(|e| panic!("Expected Ok for {url}, got: {e}"));
        }
    }

    /// SR-CRL-11: IPv6 loopback (`::1`) must be rejected. Regression test for
    /// COSMIAN-2026-020's IPv6 gap: `Url::host_str()` returns bracketed IPv6
    /// hosts (`"[::1]"`), which previously failed to parse as `IpAddr` and
    /// silently bypassed every IP-literal check.
    #[test]
    fn sr_crl_11_loopback_ipv6_blocked() {
        let err = validate_crl_url("http://[::1]/crl").unwrap_err();
        assert!(
            err.to_string().contains("loopback") || err.to_string().contains("private"),
            "Expected loopback/private error, got: {err}"
        );
    }

    /// SR-CRL-12: IPv6 unique-local addresses (`fc00::/7`, RFC 4193 — the
    /// IPv6 equivalent of RFC-1918 private space) must be rejected.
    #[test]
    fn sr_crl_12_unique_local_ipv6_blocked() {
        let err = validate_crl_url("http://[fc00::1]/crl").unwrap_err();
        assert!(
            err.to_string().contains("private") || err.to_string().contains("loopback"),
            "Expected private-IP error, got: {err}"
        );
    }

    /// SR-CRL-13: IPv6 link-local addresses (`fe80::/10`) must be rejected.
    #[test]
    fn sr_crl_13_link_local_ipv6_blocked() {
        let err = validate_crl_url("http://[fe80::1]/crl").unwrap_err();
        assert!(
            err.to_string().contains("link-local")
                || err.to_string().contains("loopback")
                || err.to_string().contains("private"),
            "Expected link-local/private error, got: {err}"
        );
    }

    /// SR-CRL-14: the IPv6 unspecified address (`::`) must be rejected.
    #[test]
    fn sr_crl_14_unspecified_ipv6_blocked() {
        let err = validate_crl_url("http://[::]/crl").unwrap_err();
        assert!(
            err.to_string().contains("loopback") || err.to_string().contains("private"),
            "Expected loopback/private error, got: {err}"
        );
    }

    /// SR-CRL-15: IPv4-mapped IPv6 addresses (`::ffff:0:0/96`, RFC 4291) must
    /// be unwrapped and the embedded IPv4 address checked, so cloud-metadata
    /// and loopback/private targets cannot be reached via this encoding.
    #[test]
    fn sr_crl_15_ipv4_mapped_ipv6_blocked() {
        for url in &[
            "http://[::ffff:127.0.0.1]/crl",
            "http://[::ffff:10.0.0.1]/crl",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
        ] {
            let err = validate_crl_url(url).unwrap_err();
            assert!(
                err.to_string().contains("loopback")
                    || err.to_string().contains("private")
                    || err.to_string().contains("link-local"),
                "Expected loopback/private/link-local error for {url}, got: {err}"
            );
        }
    }

    /// SR-CRL-16: legitimate public IPv6 URLs must pass validation.
    #[test]
    fn sr_crl_16_public_ipv6_allowed() {
        validate_crl_url("http://[2001:4860:4860::8888]/crl")
            .unwrap_or_else(|e| panic!("Expected Ok for public IPv6 URL, got: {e}"));
    }

    // ── get_crl_bytes integration tests ────────────────────────────────────────

    /// Spawn a one-shot HTTP server that immediately returns a 307 redirect.
    async fn one_shot_redirect_server(redirect_to: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            drop(stream.read(&mut buf).await);
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {redirect_to}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            drop(stream.write_all(response.as_bytes()).await);
        });
        port
    }

    /// SR-CRL-07: a 307 redirect to a loopback address must NOT be followed.
    ///
    /// The CRL-fetch client is configured with `Policy::none()` so the redirect
    /// response is returned as-is (non-2xx), preventing the KMS server from
    /// acting as an open relay to the redirected target (COSMIAN-2026-020).
    #[actix_web::test]
    async fn sr_crl_07_redirect_not_followed() {
        // "attacker-controlled" target — must never receive a request.
        let attacker_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
            // l dropped here; port is still reserved for binding by the test
        };
        let attacker_url = format!("http://127.0.0.1:{attacker_port}/secret");

        // Redirecting server.
        let redirect_port = one_shot_redirect_server(attacker_url.clone()).await;
        let crl_url = format!("http://127.0.0.1:{redirect_port}/crl.der");

        let err = get_crl_bytes(vec![crl_url], None, None).await.unwrap_err();

        // The 307 response is non-2xx, or the URL itself is blocked by SSRF
        // validation before the network call — either way get_crl_bytes must
        // return an error, not silently follow the redirect.
        assert!(
            !err.to_string().is_empty(),
            "Expected an error when CRL server returns 307, got Ok"
        );
        // Any of these mean the redirect was not followed to the attacker target:
        // – SSRF-block error (loopback/private IP rejected before network I/O), OR
        // – non-2xx status error (redirect returned as-is, not followed).
        let msg = err.to_string();
        assert!(
            msg.contains("non-success")
                || msg.contains("307")
                || msg.contains("status")
                || msg.contains("loopback")
                || msg.contains("private")
                || msg.contains("link-local"),
            "Expected SSRF-block or non-2xx status error, got: {msg}"
        );
    }

    /// SR-CRL-08: bare filesystem paths must be rejected in production code.
    #[actix_web::test]
    async fn sr_crl_08_bare_path_blocked() {
        let err = get_crl_bytes(vec!["/etc/passwd".to_owned()], None, None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not a valid URL") || msg.contains("filesystem"),
            "Expected filesystem-path error, got: {msg}"
        );
    }

    /// SR-CRL-09: a loopback URL must be rejected before any network I/O.
    #[actix_web::test]
    async fn sr_crl_09_loopback_url_blocked() {
        let err = get_crl_bytes(vec!["http://127.0.0.1:9999/crl".to_owned()], None, None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("loopback") || msg.contains("private"),
            "Expected SSRF-block error, got: {msg}"
        );
    }

    /// SR-CRL-10: `file://` URIs are permitted in test builds and resolve to disk.
    ///
    /// Creates a self-contained temp file so this test works in all CI
    /// environments regardless of whether the `test_data` submodule is present.
    #[actix_web::test]
    async fn sr_crl_10_file_uri_allowed_in_tests() {
        use std::io::Write as _;

        // Write sentinel bytes to a temp file — content does not need to be a
        // valid CRL; `get_crl_bytes` only performs I/O, not parsing.
        let mut tmp =
            tempfile::NamedTempFile::new().expect("failed to create temp file for SR-CRL-10");
        let sentinel: &[u8] = b"SR-CRL-10-sentinel";
        tmp.write_all(sentinel)
            .expect("failed to write sentinel bytes");
        tmp.flush().expect("failed to flush temp file");

        let path = tmp.path().to_str().expect("temp path is not valid UTF-8");
        // Build the canonical file URI (three slashes: scheme + empty authority + absolute path).
        let uri = format!("file://{path}");

        let result = get_crl_bytes(vec![uri.clone()], None, None)
            .await
            .expect("file:// CRL should succeed in test builds");

        assert!(
            result.contains_key(&uri),
            "Result map must contain the file:// URI as key"
        );
        assert_eq!(
            result[&uri], sentinel,
            "Returned bytes must match the sentinel written to the temp file"
        );
    }
}
