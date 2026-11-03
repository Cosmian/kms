//! Sign X.509 structures (certificates, CRLs, PKCS#10 requests) with a key that the server
//! never loads: an HSM-resident key signed through the crypto oracle.
//!
//! OpenSSL cannot sign through a KMIP/HSM callback, so the structure is built and serialised
//! by OpenSSL with a throwaway placeholder key. The DER is then decoded with `x509-cert`,
//! the signature algorithm is set to the real one (inner and outer), the to-be-signed bytes
//! (or their digest, for RSA and ECDSA: SHA-256, SHA-384 for P-384, SHA-512 for P-521) are
//! signed by the HSM, and the signature is re-inserted. The result is verified against the real
//! public key before being returned.

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_operations::Sign,
        kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm, UniqueIdentifier},
    },
    cosmian_kms_crypto::openssl::x509_signing_digest,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public},
    sign::Verifier,
    x509::{X509, X509Builder, X509Crl, X509CrlRef, X509Ref, X509Req, X509ReqRef},
};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    der::{
        Any, Decode, Encode, Sequence,
        asn1::{BitString, ObjectIdentifier, OctetString},
        oid::db::rfc5912,
    },
    request::CertReq,
    spki::AlgorithmIdentifierOwned,
};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS, ObjectHandle,
        operations::{CryptoOpSpec, SignOp},
    },
    error::KmsError,
    result::KResult,
};

/// Signature algorithm used to sign X.509 structures with a key the server cannot load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X509SignatureAlgorithm {
    Sha256WithRsa,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
    #[cfg(feature = "non-fips")]
    Ed25519,
    #[cfg(feature = "non-fips")]
    Ed448,
}

impl X509SignatureAlgorithm {
    /// RSA gives `Sha256WithRsa`; EC gives ECDSA with the digest of [`x509_signing_digest`]
    /// (RFC 5480 §4: SHA-384 for P-384, SHA-512 for P-521, SHA-256 otherwise); Ed25519/Ed448
    /// give the matching `EdDSA` variant (non-FIPS builds only).
    pub(crate) fn for_public_key<T: HasPublic>(key: &PKeyRef<T>) -> KResult<Self> {
        match key.id() {
            Id::RSA => Ok(Self::Sha256WithRsa),
            Id::EC => Ok(match x509_signing_digest(key).type_() {
                Nid::SHA384 => Self::EcdsaWithSha384,
                Nid::SHA512 => Self::EcdsaWithSha512,
                _ => Self::EcdsaWithSha256,
            }),
            #[cfg(feature = "non-fips")]
            Id::ED25519 => Ok(Self::Ed25519),
            #[cfg(feature = "non-fips")]
            Id::ED448 => Ok(Self::Ed448),
            id => Err(KmsError::NotSupported(format!(
                "X.509 signing with an HSM key supports RSA, EC and EdDSA keys only, got {id:?}"
            ))),
        }
    }

    /// KMIP Sign parameters matching the algorithm identifier written in the structure.
    ///
    /// They must always be explicit: the crypto oracle must use the hash named by the OID.
    pub(crate) fn sign_parameters(self) -> CryptographicParameters {
        let digital_signature_algorithm = match self {
            Self::Sha256WithRsa => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
            Self::EcdsaWithSha256 => DigitalSignatureAlgorithm::ECDSAWithSHA256,
            Self::EcdsaWithSha384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
            Self::EcdsaWithSha512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
            #[cfg(feature = "non-fips")]
            Self::Ed25519 | Self::Ed448 => {
                return CryptographicParameters {
                    cryptographic_algorithm: Some(if self == Self::Ed25519 {
                        CryptographicAlgorithm::Ed25519
                    } else {
                        CryptographicAlgorithm::Ed448
                    }),
                    ..CryptographicParameters::default()
                };
            }
        };
        CryptographicParameters {
            digital_signature_algorithm: Some(digital_signature_algorithm),
            ..CryptographicParameters::default()
        }
    }

    /// The digest of the signature: SHA-2 for RSA and ECDSA, null for `EdDSA` (which hashes
    /// internally).
    pub(crate) fn digest(self) -> MessageDigest {
        match self {
            Self::Sha256WithRsa | Self::EcdsaWithSha256 => MessageDigest::sha256(),
            Self::EcdsaWithSha384 => MessageDigest::sha384(),
            Self::EcdsaWithSha512 => MessageDigest::sha512(),
            #[cfg(feature = "non-fips")]
            Self::Ed25519 | Self::Ed448 => MessageDigest::null(),
        }
    }

    /// `true` when the signer signs the [`digest`](Self::digest) of the data (RSA, ECDSA);
    /// `false` when it signs the raw data (`EdDSA` cannot take a digest).
    const fn prehashed(self) -> bool {
        matches!(
            self,
            Self::Sha256WithRsa
                | Self::EcdsaWithSha256
                | Self::EcdsaWithSha384
                | Self::EcdsaWithSha512
        )
    }

    fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        // RFC 4055 §5: RSA parameters are NULL; RFC 5758 §3.2 / RFC 8410 §3: ECDSA and EdDSA
        // parameters MUST be absent
        let (oid, parameters) = match self {
            Self::Sha256WithRsa => (rfc5912::SHA_256_WITH_RSA_ENCRYPTION, Some(Any::null())),
            Self::EcdsaWithSha256 => (rfc5912::ECDSA_WITH_SHA_256, None),
            Self::EcdsaWithSha384 => (rfc5912::ECDSA_WITH_SHA_384, None),
            Self::EcdsaWithSha512 => (rfc5912::ECDSA_WITH_SHA_512, None),
            #[cfg(feature = "non-fips")]
            Self::Ed25519 => (der::oid::db::rfc8410::ID_ED_25519, None),
            #[cfg(feature = "non-fips")]
            Self::Ed448 => (der::oid::db::rfc8410::ID_ED_448, None),
        };
        AlgorithmIdentifierOwned { oid, parameters }
    }
}

/// HSM-resident signing key: referenced by UID, never loaded.
pub(crate) struct OracleSigningKey {
    /// Full HSM UID, e.g. `hsm::0::subca`.
    pub(crate) uid: String,
    /// Crypto-oracle prefix from `ObjectHandle::Hsm`.
    prefix: String,
    pub(crate) algorithm: X509SignatureAlgorithm,
    pub(crate) public_key: PKey<Public>,
}

impl OracleSigningKey {
    /// `None` when `uid` is not an HSM UID.
    pub(crate) fn for_hsm_uid(uid: &str, public_key: PKey<Public>) -> KResult<Option<Self>> {
        let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(uid) else {
            return Ok(None);
        };
        Ok(Some(Self {
            uid: uid.to_owned(),
            prefix: prefix.to_owned(),
            algorithm: X509SignatureAlgorithm::for_public_key(&public_key)?,
            public_key,
        }))
    }
}

/// Fresh EC P-256 key used only so OpenSSL can serialise a structure; its signature is
/// always replaced.
pub(crate) fn placeholder_signing_key() -> KResult<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

/// A DER structure of the form `SEQUENCE { to-be-signed, signatureAlgorithm, signature }`.
trait ReSignable: Sized + for<'a> Decode<'a> + Encode {
    /// Set the signature algorithm. For certificates and CRLs, both the inner (signed) and the
    /// outer identifier, which must be equal.
    fn set_algorithm(&mut self, algorithm: AlgorithmIdentifierOwned);
    fn tbs_der(&self) -> x509_cert::der::Result<Vec<u8>>;
    fn set_signature(&mut self, signature: BitString);
}

impl ReSignable for CertReq {
    fn set_algorithm(&mut self, algorithm: AlgorithmIdentifierOwned) {
        self.algorithm = algorithm;
    }

    fn tbs_der(&self) -> x509_cert::der::Result<Vec<u8>> {
        self.info.to_der()
    }

    fn set_signature(&mut self, signature: BitString) {
        self.signature = signature;
    }
}

impl ReSignable for Certificate {
    fn set_algorithm(&mut self, algorithm: AlgorithmIdentifierOwned) {
        self.tbs_certificate.signature = algorithm.clone();
        self.signature_algorithm = algorithm;
    }

    fn tbs_der(&self) -> x509_cert::der::Result<Vec<u8>> {
        self.tbs_certificate.to_der()
    }

    fn set_signature(&mut self, signature: BitString) {
        self.signature = signature;
    }
}

impl ReSignable for CertificateList {
    fn set_algorithm(&mut self, algorithm: AlgorithmIdentifierOwned) {
        self.tbs_cert_list.signature = algorithm.clone();
        self.signature_algorithm = algorithm;
    }

    fn tbs_der(&self) -> x509_cert::der::Result<Vec<u8>> {
        self.tbs_cert_list.to_der()
    }

    fn set_signature(&mut self, signature: BitString) {
        self.signature = signature;
    }
}

/// RFC 6960 `OCSPResponse`.
#[derive(Clone, Debug, Sequence)]
struct OcspResponse {
    response_status: Any,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    response_bytes: Option<ResponseBytes>,
}

/// RFC 6960 `ResponseBytes`.
#[derive(Clone, Debug, Sequence)]
struct ResponseBytes {
    response_type: ObjectIdentifier,
    response: OctetString,
}

/// RFC 6960 `BasicOCSPResponse`; the signed part is kept as opaque DER.
#[derive(Clone, Debug, Sequence)]
struct BasicOcspResponse {
    tbs_response_data: Any,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    certs: Option<Vec<Certificate>>,
}

impl ReSignable for BasicOcspResponse {
    // OCSP has no inner copy of the algorithm identifier
    fn set_algorithm(&mut self, algorithm: AlgorithmIdentifierOwned) {
        self.signature_algorithm = algorithm;
    }

    fn tbs_der(&self) -> x509_cert::der::Result<Vec<u8>> {
        self.tbs_response_data.to_der()
    }

    fn set_signature(&mut self, signature: BitString) {
        self.signature = signature;
    }
}

fn der_error(what: &str, e: impl std::fmt::Display) -> KmsError {
    KmsError::ServerError(format!("{what}: {e}"))
}

/// Set `algorithm` on `structure` and return its to-be-signed DER.
fn resign_parts<T: ReSignable>(
    structure: &mut T,
    algorithm: X509SignatureAlgorithm,
) -> KResult<Vec<u8>> {
    structure.set_algorithm(algorithm.algorithm_identifier());
    structure
        .tbs_der()
        .map_err(|e| der_error("encoding the to-be-signed structure", e))
}

/// Decode the placeholder-signed DER, set `algorithm`, return the structure and the DER of
/// its to-be-signed part.
fn prepare<T: ReSignable>(
    placeholder_der: &[u8],
    algorithm: X509SignatureAlgorithm,
) -> KResult<(T, Vec<u8>)> {
    let mut structure =
        T::from_der(placeholder_der).map_err(|e| der_error("decoding X.509 structure", e))?;
    let tbs = resign_parts(&mut structure, algorithm)?;
    Ok((structure, tbs))
}

/// Insert `signature` and return the DER of the signed structure.
fn assemble<T: ReSignable>(mut structure: T, signature: &[u8]) -> KResult<Vec<u8>> {
    structure.set_signature(
        BitString::from_bytes(signature).map_err(|e| der_error("encoding the signature", e))?,
    );
    structure
        .to_der()
        .map_err(|e| der_error("encoding the signed structure", e))
}

/// Prepare a PKCS#10 request built by OpenSSL for signing with `algorithm`: returns the request
/// and the to-be-signed DER to pass to [`oracle_sign`].
pub(crate) fn prepare_csr(
    draft: &X509ReqRef,
    algorithm: X509SignatureAlgorithm,
) -> KResult<(CertReq, Vec<u8>)> {
    prepare(&draft.to_der()?, algorithm)
}

/// Insert the externally produced `signature` in a request prepared by [`prepare_csr`].
pub(crate) fn assemble_csr(req: CertReq, signature: &[u8]) -> KResult<X509Req> {
    Ok(X509Req::from_der(&assemble(req, signature)?)?)
}

/// Sign the to-be-signed DER `tbs` with the HSM key through the crypto oracle, using the exact
/// `key.uid`. RSA and ECDSA sign its digest ([`X509SignatureAlgorithm::digest`]), `EdDSA` signs
/// it directly.
///
/// Never goes through keyset/rotation resolution: a bare HSM UID passed to `kms.sign` resolves
/// to the latest generation, which would not match the issuer certificate's public key.
/// No permission check here: callers authorise the key first (Certify / CRL / CSR / OCSP).
pub(crate) async fn oracle_sign(kms: &KMS, key: &OracleSigningKey, tbs: &[u8]) -> KResult<Vec<u8>> {
    let (data, digested_data) = if key.algorithm.prehashed() {
        (None, Some(hash(key.algorithm.digest(), tbs)?.to_vec()))
    } else {
        (Some(Zeroizing::from(tbs.to_vec())), None)
    };
    let request = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(key.uid.clone())),
        cryptographic_parameters: Some(key.algorithm.sign_parameters()),
        data,
        digested_data,
        ..Sign::default()
    };
    <SignOp as CryptoOpSpec>::execute_oracle(kms, &request, &key.uid, &key.prefix)
        .await?
        .signature_data
        .ok_or_else(|| KmsError::ServerError("crypto oracle returned no signature".to_owned()))
}

/// Verify `signature` over `tbs` made with `algorithm`, for structures OpenSSL cannot verify
/// itself (OCSP responses are checked after parsing, not at signing time).
fn verify_external_signature<T: HasPublic>(
    public_key: &PKeyRef<T>,
    algorithm: X509SignatureAlgorithm,
    tbs: &[u8],
    signature: &[u8],
) -> KResult<bool> {
    let mut verifier = if algorithm.prehashed() {
        Verifier::new(algorithm.digest(), public_key)?
    } else {
        Verifier::new_without_digest(public_key)?
    };
    Ok(verifier.verify_oneshot(signature, tbs)?)
}

async fn sign_with_oracle<T: ReSignable>(
    kms: &KMS,
    key: &OracleSigningKey,
    placeholder_der: &[u8],
) -> KResult<Vec<u8>> {
    let (structure, tbs) = prepare::<T>(placeholder_der, key.algorithm)?;
    let signature = oracle_sign(kms, key, &tbs).await?;
    assemble(structure, &signature)
}

/// Replace the placeholder signature of `draft` with the HSM signature; the result is verified
/// with the key's public key.
pub(crate) async fn sign_certificate_with_oracle(
    kms: &KMS,
    key: &OracleSigningKey,
    draft: &X509Ref,
) -> KResult<X509> {
    let placeholder_der = draft.to_der()?;
    let der = sign_with_oracle::<Certificate>(kms, key, &placeholder_der).await?;
    let certificate = X509::from_der(&der)?;
    if !certificate.verify(&key.public_key)? {
        return Err(KmsError::InvalidRequest(
            "HSM signature over the certificate does not verify with the issuer certificate \
             public key: the HSM private key does not match the issuer certificate"
                .to_owned(),
        ));
    }
    Ok(certificate)
}

/// Same as [`sign_certificate_with_oracle`] for a CRL.
pub(crate) async fn sign_crl_with_oracle(
    kms: &KMS,
    key: &OracleSigningKey,
    draft: &X509CrlRef,
) -> KResult<X509Crl> {
    let placeholder_der = draft.to_der()?;
    let der = sign_with_oracle::<CertificateList>(kms, key, &placeholder_der).await?;
    let crl = X509Crl::from_der(&der)?;
    if !crl.verify(&key.public_key)? {
        return Err(KmsError::InvalidRequest(
            "HSM signature over the CRL does not verify with the issuer certificate public key: \
             the HSM private key does not match the issuer certificate"
                .to_owned(),
        ));
    }
    Ok(crl)
}

/// Self-signed v3 certificate with `signer`'s subject and validity but the `placeholder` key.
///
/// Passed to the OCSP response builder in place of the real signer certificate (whose key is in
/// the HSM): the builder derives the responder ID (by name) from it, and the result is re-signed
/// by [`sign_ocsp_response_with_oracle`].
pub(crate) fn placeholder_signer_certificate(
    signer: &X509Ref,
    placeholder: &PKeyRef<Private>,
) -> KResult<X509> {
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(signer.subject_name())?;
    builder.set_issuer_name(signer.subject_name())?;
    builder.set_pubkey(placeholder)?;
    builder.set_not_before(signer.not_before())?;
    builder.set_not_after(signer.not_after())?;
    builder.sign(placeholder, MessageDigest::sha256())?;
    Ok(builder.build())
}

fn response_bytes_mut(response: &mut OcspResponse) -> KResult<&mut ResponseBytes> {
    response
        .response_bytes
        .as_mut()
        .ok_or_else(|| KmsError::ServerError("OCSP response without responseBytes".to_owned()))
}

/// Decode a DER `OCSPResponse` built with [`placeholder_signer_certificate`], swap the embedded
/// placeholder certificate (if any) for `signer`, set `algorithm` and return the decoded
/// response, its basic response and the to-be-signed DER.
fn prepare_ocsp_response(
    placeholder_der: &[u8],
    signer: &X509Ref,
    algorithm: X509SignatureAlgorithm,
) -> KResult<(OcspResponse, BasicOcspResponse, Vec<u8>)> {
    let mut response = OcspResponse::from_der(placeholder_der)
        .map_err(|e| der_error("decoding the OCSP response", e))?;
    let mut basic =
        BasicOcspResponse::from_der(response_bytes_mut(&mut response)?.response.as_bytes())
            .map_err(|e| der_error("decoding the basic OCSP response", e))?;
    if basic.certs.is_some() {
        basic.certs =
            Some(vec![Certificate::from_der(&signer.to_der()?).map_err(
                |e| der_error("decoding the signer certificate", e),
            )?]);
    }
    let tbs = resign_parts(&mut basic, algorithm)?;
    Ok((response, basic, tbs))
}

/// Insert `signature` in `basic` and return the DER of the `OCSPResponse` wrapping it.
fn assemble_ocsp_response(
    mut response: OcspResponse,
    basic: BasicOcspResponse,
    signature: &[u8],
) -> KResult<Vec<u8>> {
    response_bytes_mut(&mut response)?.response = OctetString::new(assemble(basic, signature)?)
        .map_err(|e| der_error("encoding the basic OCSP response", e))?;
    response
        .to_der()
        .map_err(|e| der_error("encoding the OCSP response", e))
}

/// Replace the placeholder signature (and embedded placeholder certificate, if any) of a DER
/// `OCSPResponse` built with [`placeholder_signer_certificate`] by the HSM signature of the real
/// `signer`. Returns the DER of the signed response.
pub(crate) async fn sign_ocsp_response_with_oracle(
    kms: &KMS,
    key: &OracleSigningKey,
    signer: &X509Ref,
    placeholder_der: &[u8],
) -> KResult<Vec<u8>> {
    let (response, basic, tbs) = prepare_ocsp_response(placeholder_der, signer, key.algorithm)?;
    let signature = oracle_sign(kms, key, &tbs).await?;
    if !verify_external_signature(&key.public_key, key.algorithm, &tbs, &signature)? {
        return Err(KmsError::ServerError(
            "HSM signature over the OCSP response does not verify with the signer public key"
                .to_owned(),
        ));
    }
    assemble_ocsp_response(response, basic, &signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::{
        crl::build_crl,
        ocsp::{OcspBuildConfig, OcspCertStatus, OcspStatusEntry, build_ocsp_response},
    };
    use openssl::{
        asn1::Asn1Time,
        ocsp::{
            OcspCertId, OcspCertStatus as OpenSslStatus, OcspFlag, OcspRequest,
            OcspResponse as OpenSslOcspResponse,
        },
        pkey::{PKey, Private},
        rsa::Rsa,
        sign::Signer,
        stack::Stack,
        x509::{
            X509NameBuilder, X509ReqBuilder, extension::BasicConstraints, store::X509StoreBuilder,
        },
    };

    use super::*;

    fn rsa_key() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    }

    fn ec_key() -> PKey<Private> {
        placeholder_signing_key().unwrap()
    }

    fn ec_key_on(curve: Nid) -> PKey<Private> {
        let group = EcGroup::from_curve_name(curve).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// Software stand-in for the HSM: RSA PKCS#1 v1.5 / ECDSA over the digest the oracle is
    /// asked to use, or pure `EdDSA` over the raw to-be-signed bytes.
    fn sign_tbs(key: &PKey<Private>, tbs: &[u8]) -> Vec<u8> {
        let algorithm = X509SignatureAlgorithm::for_public_key(key).unwrap();
        let mut signer = if algorithm.prehashed() {
            Signer::new(algorithm.digest(), key).unwrap()
        } else {
            Signer::new_without_digest(key).unwrap()
        };
        signer.sign_oneshot_to_vec(tbs).unwrap()
    }

    fn name(cn: &str) -> openssl::x509::X509Name {
        let mut b = X509NameBuilder::new().unwrap();
        b.append_entry_by_text("CN", cn).unwrap();
        b.build()
    }

    fn public_of(key: &PKey<Private>) -> PKey<Public> {
        PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap()
    }

    fn certificate(
        subject: &str,
        subject_key: &PKey<Private>,
        issuer: &str,
        serial: u32,
        ca: bool,
    ) -> X509Builder {
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name(subject)).unwrap();
        b.set_issuer_name(&name(issuer)).unwrap();
        b.set_pubkey(subject_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(10).unwrap())
            .unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        b
    }

    fn draft_certificate(subject_key: &PKey<Private>) -> X509 {
        let mut b = certificate("subject", subject_key, "issuer", 7, false);
        b.sign(&placeholder_signing_key().unwrap(), MessageDigest::sha256())
            .unwrap();
        b.build()
    }

    fn resign_all_structures(key: &PKey<Private>, oid: &str) {
        let algorithm = X509SignatureAlgorithm::for_public_key(key).unwrap();
        let public = public_of(key);

        let mut b = X509ReqBuilder::new().unwrap();
        b.set_version(0).unwrap();
        b.set_subject_name(&name("csr")).unwrap();
        b.set_pubkey(key).unwrap();
        b.sign(&placeholder_signing_key().unwrap(), MessageDigest::sha256())
            .unwrap();
        let (req, tbs) = prepare_csr(&b.build(), algorithm).unwrap();
        let csr = assemble_csr(req, &sign_tbs(key, &tbs)).unwrap();
        assert!(csr.verify(&public).unwrap());
        let der = csr.to_der().unwrap();
        let (_, parsed) = <x509_parser::certification_request::X509CertificationRequest as x509_parser::prelude::FromDer<'_, x509_parser::error::X509Error>>::from_der(&der).unwrap();
        assert_eq!(parsed.signature_algorithm.algorithm.to_id_string(), oid);

        let draft = draft_certificate(key);
        let (cert, tbs) = prepare::<Certificate>(&draft.to_der().unwrap(), algorithm).unwrap();
        let der = assemble(cert, &sign_tbs(key, &tbs)).unwrap();
        assert!(X509::from_der(&der).unwrap().verify(&public).unwrap());
        // the signed inner algorithm identifier equals the outer one
        let parsed = Certificate::from_der(&der).unwrap();
        assert_eq!(parsed.tbs_certificate.signature, parsed.signature_algorithm);
        assert_eq!(parsed.signature_algorithm.oid.to_string(), oid);

        let draft = build_crl(&draft, &placeholder_signing_key().unwrap(), &[], 1, 7).unwrap();
        let (crl, tbs) = prepare::<CertificateList>(&draft.to_der().unwrap(), algorithm).unwrap();
        let der = assemble(crl, &sign_tbs(key, &tbs)).unwrap();
        assert!(X509Crl::from_der(&der).unwrap().verify(&public).unwrap());
    }

    #[test]
    fn resign_rsa_and_ec() {
        resign_all_structures(&rsa_key(), "1.2.840.113549.1.1.11");
        resign_all_structures(&ec_key(), "1.2.840.10045.4.3.2");
    }

    /// RFC 5480 §4: the ECDSA digest follows the issuer curve (P-384 → SHA-384, P-521 →
    /// SHA-512) in the OID, the oracle Sign parameters and the in-process signing digest.
    #[test]
    fn ec_digest_matches_issuer_curve() {
        for (curve, oid, kmip, digest) in [
            (
                Nid::X9_62_PRIME256V1,
                "1.2.840.10045.4.3.2",
                DigitalSignatureAlgorithm::ECDSAWithSHA256,
                Nid::SHA256,
            ),
            (
                Nid::SECP384R1,
                "1.2.840.10045.4.3.3",
                DigitalSignatureAlgorithm::ECDSAWithSHA384,
                Nid::SHA384,
            ),
            (
                Nid::SECP521R1,
                "1.2.840.10045.4.3.4",
                DigitalSignatureAlgorithm::ECDSAWithSHA512,
                Nid::SHA512,
            ),
        ] {
            let key = ec_key_on(curve);
            resign_all_structures(&key, oid);
            ocsp_resign(&key);
            let algorithm = X509SignatureAlgorithm::for_public_key(&key).unwrap();
            assert_eq!(
                algorithm.sign_parameters().digital_signature_algorithm,
                Some(kmip)
            );
            assert_eq!(x509_signing_digest(&key).type_(), digest);
        }
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn eddsa_certificate_csr_and_crl_resign() {
        resign_all_structures(&PKey::generate_ed25519().unwrap(), "1.3.101.112");
        resign_all_structures(&PKey::generate_ed448().unwrap(), "1.3.101.113");
        // RFC 8410 §3: no parameters
        let key = PKey::generate_ed25519().unwrap();
        let algorithm = X509SignatureAlgorithm::for_public_key(&key).unwrap();
        assert!(algorithm.algorithm_identifier().parameters.is_none());
        assert!(!algorithm.prehashed());
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn for_public_key_rejects_other_types() {
        let key = PKey::generate_x25519().unwrap();
        assert!(matches!(
            X509SignatureAlgorithm::for_public_key(&key),
            Err(KmsError::NotSupported(_))
        ));
    }

    fn ocsp_resign(ca_key: &PKey<Private>) {
        let algorithm = X509SignatureAlgorithm::for_public_key(ca_key).unwrap();
        let mut b = certificate("ca", ca_key, "ca", 1, true);
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        let ca = b.build();
        let leaf_key = ec_key();
        let mut b = certificate("leaf", &leaf_key, "ca", 7, false);
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        let leaf = b.build();

        let mut request = OcspRequest::new().unwrap();
        request
            .add_id(OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &ca).unwrap())
            .unwrap();
        let entries = [OcspStatusEntry {
            serial_hex: leaf
                .serial_number()
                .to_bn()
                .unwrap()
                .to_hex_str()
                .unwrap()
                .to_string(),
            status: OcspCertStatus::Good,
        }];

        let placeholder = placeholder_signing_key().unwrap();
        let placeholder_cert = placeholder_signer_certificate(&ca, &placeholder).unwrap();
        let built = build_ocsp_response(
            &request.to_der().unwrap(),
            &ca,
            &placeholder_cert,
            &placeholder,
            &entries,
            &OcspBuildConfig {
                include_signer_cert: true,
                ..OcspBuildConfig::default()
            },
        )
        .unwrap();

        let (response, basic, tbs) = prepare_ocsp_response(&built, &ca, algorithm).unwrap();
        let signature = sign_tbs(ca_key, &tbs);
        assert!(
            verify_external_signature(&public_of(ca_key), algorithm, &tbs, &signature).unwrap()
        );
        let der = assemble_ocsp_response(response, basic, &signature).unwrap();

        let parsed = OpenSslOcspResponse::from_der(&der).unwrap();
        let basic = parsed.basic().unwrap();
        let mut trusted = X509StoreBuilder::new().unwrap();
        trusted.add_cert(ca.clone()).unwrap();
        let mut others = Stack::new().unwrap();
        others.push(ca.clone()).unwrap();
        basic
            .verify(&others, &trusted.build(), OcspFlag::empty())
            .unwrap();
        let id = OcspCertId::from_cert(MessageDigest::sha1(), &leaf, &ca).unwrap();
        let status = basic.find_status(&id).unwrap();
        assert_eq!(status.status, OpenSslStatus::GOOD);
        // the embedded certificate is the real signer, not the placeholder
        let embedded = Certificate::from_der(&ca.to_der().unwrap()).unwrap();
        let basic_struct = BasicOcspResponse::from_der(
            OcspResponse::from_der(&der)
                .unwrap()
                .response_bytes
                .unwrap()
                .response
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(basic_struct.certs, Some(vec![embedded]));
    }

    #[test]
    fn ocsp_response_resign() {
        ocsp_resign(&rsa_key());
        ocsp_resign(&ec_key());
    }
}
