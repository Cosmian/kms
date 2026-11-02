use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::kmip_private_key_to_openssl;
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    sign::Verifier,
};
use ssh_key::{Algorithm, Certificate, EcdsaCurve, PublicKey};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS, ObjectHandle,
        certificate::oracle_signing::{OracleSigningKey, X509SignatureAlgorithm, oracle_sign},
        operations::algorithm_policy::enforce_kmip_algorithm_policy_for_public_key,
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

#[derive(Clone, Copy)]
pub(crate) enum SshSignatureAlgorithm {
    RsaSha256,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    #[cfg(feature = "non-fips")]
    Ed25519,
}

impl SshSignatureAlgorithm {
    pub(crate) fn from_public_key(key: &PKey<Public>) -> KResult<Self> {
        if key.id() == Id::RSA && key.rsa()?.n().num_bits() < 2048 {
            return Err(KmsError::NotSupported(
                "OpenSSH CA RSA keys must be at least 2048 bits".to_owned(),
            ));
        }
        match X509SignatureAlgorithm::for_public_key(key)? {
            X509SignatureAlgorithm::Sha256WithRsa => Ok(Self::RsaSha256),
            X509SignatureAlgorithm::EcdsaWithSha256 => Ok(Self::EcdsaSha256),
            X509SignatureAlgorithm::EcdsaWithSha384 => Ok(Self::EcdsaSha384),
            X509SignatureAlgorithm::EcdsaWithSha512 => Ok(Self::EcdsaSha512),
            #[cfg(feature = "non-fips")]
            X509SignatureAlgorithm::Ed25519 => Ok(Self::Ed25519),
            #[cfg(feature = "non-fips")]
            X509SignatureAlgorithm::Ed448 => Err(KmsError::NotSupported(
                "OpenSSH CA signing with Ed448 is not supported".to_owned(),
            )),
        }
    }

    fn ssh_name(self, key: &PublicKey) -> KResult<&'static str> {
        match self {
            Self::RsaSha256 => Ok("rsa-sha2-256"),
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512 => match key.algorithm() {
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                } => Ok("ecdsa-sha2-nistp256"),
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384,
                } => Ok("ecdsa-sha2-nistp384"),
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP521,
                } => Ok("ecdsa-sha2-nistp521"),
                _ => Err(KmsError::NotSupported(
                    "OpenSSH ECDSA signature requires a NIST EC key".to_owned(),
                )),
            },
            #[cfg(feature = "non-fips")]
            Self::Ed25519 => Ok("ssh-ed25519"),
        }
    }

    fn digest(self) -> MessageDigest {
        match self {
            Self::RsaSha256 | Self::EcdsaSha256 => MessageDigest::sha256(),
            Self::EcdsaSha384 => MessageDigest::sha384(),
            Self::EcdsaSha512 => MessageDigest::sha512(),
            #[cfg(feature = "non-fips")]
            Self::Ed25519 => MessageDigest::null(),
        }
    }

    fn kmip_parameters(self) -> cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters{
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
            CryptographicParameters, DigitalSignatureAlgorithm,
        };

        match self {
            Self::RsaSha256 => CryptographicParameters {
                digital_signature_algorithm: Some(
                    DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                ),
                ..CryptographicParameters::default()
            },
            Self::EcdsaSha256 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..CryptographicParameters::default()
            },
            Self::EcdsaSha384 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA384),
                ..CryptographicParameters::default()
            },
            Self::EcdsaSha512 => CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA512),
                ..CryptographicParameters::default()
            },
            #[cfg(feature = "non-fips")]
            Self::Ed25519 => CryptographicParameters {
                cryptographic_algorithm: Some(
                    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::Ed25519,
                ),
                ..CryptographicParameters::default()
            },
        }
    }
}

pub(crate) fn open_ssh_public_key(key: &PKey<Public>) -> KResult<String> {
    let bytes = match key.id() {
        Id::RSA => {
            let rsa = key.rsa()?;
            let mut output = Vec::new();
            put_string(&mut output, b"ssh-rsa")?;
            put_mpint(&mut output, &rsa.e().to_vec())?;
            put_mpint(&mut output, &rsa.n().to_vec())?;
            output
        }
        Id::EC => {
            let ec = key.ec_key()?;
            let curve = ec.group().curve_name().ok_or_else(|| {
                KmsError::NotSupported("OpenSSH requires a named NIST EC curve".to_owned())
            })?;
            let (algorithm, curve_name) = match curve {
                Nid::X9_62_PRIME256V1 => ("ecdsa-sha2-nistp256", "nistp256"),
                Nid::SECP384R1 => ("ecdsa-sha2-nistp384", "nistp384"),
                Nid::SECP521R1 => ("ecdsa-sha2-nistp521", "nistp521"),
                _ => {
                    return Err(KmsError::NotSupported(
                        "OpenSSH CA requires a NIST P-256, P-384, or P-521 key".to_owned(),
                    ));
                }
            };
            let mut context = BigNumContext::new()?;
            let point = ec.public_key().to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut context,
            )?;
            let mut output = Vec::new();
            put_string(&mut output, algorithm.as_bytes())?;
            put_string(&mut output, curve_name.as_bytes())?;
            put_string(&mut output, &point)?;
            output
        }
        #[cfg(feature = "non-fips")]
        Id::ED25519 => {
            let mut output = Vec::new();
            put_string(&mut output, b"ssh-ed25519")?;
            put_string(&mut output, &key.raw_public_key()?)?;
            output
        }
        other => {
            return Err(KmsError::NotSupported(format!(
                "OpenSSH CA public key type {other:?} is not supported"
            )));
        }
    };
    PublicKey::from_bytes(&bytes)
        .and_then(|public_key| public_key.to_openssh())
        .map_err(|e| KmsError::InvalidRequest(format!("encoding OpenSSH public key: {e}")))
}

pub(crate) async fn ca_public_key(
    kms: &KMS,
    key_uid: &str,
    user: &UserId,
) -> KResult<(PKey<Public>, String, bool)> {
    let key = retrieve_object_for_operation(
        ObjectHandle::from(key_uid),
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation::Sign,
        kms,
        user,
    )
    .await?;
    if key.effective_state()
        != cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::State::Active
    {
        return Err(KmsError::InvalidRequest(format!(
            "SSH CA key '{}' is not Active",
            key.id()
        )));
    }
    let is_hsm = ObjectHandle::from(key.id()).is_hsm();
    let public_key = if is_hsm {
        let public_uid = format!(
            "{}{}",
            key.id(),
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::extra::tagging::SYSTEM_TAG_PUBLIC_KEY
        );
        let public_object = kms
            .database
            .retrieve_object_arc(&public_uid)
            .await?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("SSH CA public key '{public_uid}' not found"))
            })?;
        let unwrapped = Box::pin(kms.get_unwrapped(
            public_object.id(),
            public_object.object(),
            public_object.owner_id(),
        ))
        .await?;
        cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::kmip_public_key_to_openssl(&unwrapped)?
    } else {
        let unwrapped = Box::pin(kms.get_unwrapped(key.id(), key.object(), user)).await?;
        let private_key = kmip_private_key_to_openssl(&unwrapped)?;
        validate_ca_key_algorithm(&private_key)?;
        PKey::public_key_from_der(&private_key.public_key_to_der()?)?
    };
    enforce_kmip_algorithm_policy_for_public_key(
        &kms.params,
        "SSH CA Sign",
        &public_key,
        key.object().attributes().ok(),
    )?;
    SshSignatureAlgorithm::from_public_key(&public_key)?;
    let ssh_key = open_ssh_public_key(&public_key)?;
    Ok((public_key, ssh_key, is_hsm))
}

pub(crate) async fn sign_certificate_payload(
    kms: &KMS,
    key_uid: &str,
    user: &UserId,
    payload: &[u8],
    public_key: &PKey<Public>,
    is_hsm: bool,
) -> KResult<(SshSignatureAlgorithm, Vec<u8>)> {
    let algorithm = SshSignatureAlgorithm::from_public_key(public_key)?;
    let signature = if is_hsm {
        let signer =
            OracleSigningKey::for_hsm_uid(key_uid, public_key.clone())?.ok_or_else(|| {
                KmsError::InvalidRequest("configured SSH CA is not an HSM key".to_owned())
            })?;
        oracle_sign(kms, &signer, payload).await?
    } else {
        kms
            .sign(
                cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Sign {
                    unique_identifier: Some(
                        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(key_uid.to_owned()),
                    ),
                    cryptographic_parameters: Some(algorithm.kmip_parameters()),
                    data: Some(Zeroizing::new(payload.to_vec())),
                    ..Default::default()
                },
                user,
            )
            .await?
            .signature_data
            .ok_or_else(|| KmsError::ServerError("KMS returned no SSH certificate signature".to_owned()))?
    };
    verify_signature(public_key, algorithm, payload, &signature)?;
    Ok((algorithm, signature))
}

pub(crate) struct CertificateTbs<'a> {
    pub(crate) subject: &'a PublicKey,
    pub(crate) ca: &'a PublicKey,
    pub(crate) role: &'a str,
    pub(crate) principals: &'a [String],
    pub(crate) valid_after: u64,
    pub(crate) valid_before: u64,
    pub(crate) serial: u64,
    pub(crate) nonce: &'a [u8],
}

pub(crate) fn build_certificate_tbs(input: &CertificateTbs<'_>) -> KResult<Vec<u8>> {
    let CertificateTbs {
        subject,
        ca,
        role,
        principals,
        valid_after,
        valid_before,
        serial,
        nonce,
    } = input;
    let cert_name = subject.algorithm().to_certificate_type();
    if !matches!(
        subject.algorithm(),
        Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. } | Algorithm::Ed25519
    ) {
        return Err(KmsError::InvalidRequest(
            "SSH subject public-key algorithm is not supported".to_owned(),
        ));
    }
    let subject_bytes = subject
        .to_bytes()
        .map_err(|e| KmsError::InvalidRequest(format!("encoding subject public key: {e}")))?;
    let ca_bytes = ca
        .to_bytes()
        .map_err(|e| KmsError::InvalidRequest(format!("encoding SSH CA public key: {e}")))?;
    let key_fields = strip_algorithm(&subject_bytes)?;
    let mut tbs = Vec::new();
    put_string(&mut tbs, cert_name.as_bytes())?;
    put_string(&mut tbs, nonce)?;
    tbs.extend_from_slice(key_fields);
    tbs.extend_from_slice(&serial.to_be_bytes());
    tbs.extend_from_slice(&1_u32.to_be_bytes());
    put_string(&mut tbs, role.as_bytes())?;
    let mut encoded_principals = Vec::new();
    for principal in *principals {
        put_string(&mut encoded_principals, principal.as_bytes())?;
    }
    put_string(&mut tbs, &encoded_principals)?;
    tbs.extend_from_slice(&valid_after.to_be_bytes());
    tbs.extend_from_slice(&valid_before.to_be_bytes());
    put_string(&mut tbs, &[])?;
    let mut extensions = Vec::new();
    put_string(&mut extensions, b"permit-pty")?;
    put_string(&mut extensions, &[])?;
    put_string(&mut tbs, &extensions)?;
    put_string(&mut tbs, &[])?;
    put_string(&mut tbs, &ca_bytes)?;

    validate_subject_algorithm(subject)?;
    Ok(tbs)
}

pub(crate) fn finish_certificate(
    tbs: &[u8],
    ca: &PublicKey,
    algorithm: SshSignatureAlgorithm,
    signature: &[u8],
) -> KResult<String> {
    let signature_bytes = encode_signature(algorithm, ca, signature)?;
    let mut certificate = tbs.to_vec();
    put_string(&mut certificate, &signature_bytes)?;
    let parsed = Certificate::from_bytes(&certificate)
        .map_err(|e| KmsError::ServerError(format!("encoding SSH certificate: {e}")))?;
    if parsed
        .to_bytes()
        .map_err(|e| KmsError::ServerError(format!("validating SSH certificate: {e}")))?
        != certificate
    {
        return Err(KmsError::ServerError(
            "SSH certificate encoding changed after signature generation".to_owned(),
        ));
    }
    parsed
        .to_openssh()
        .map_err(|e| KmsError::ServerError(format!("encoding SSH certificate: {e}")))
}

fn encode_signature(
    algorithm: SshSignatureAlgorithm,
    ca: &PublicKey,
    signature: &[u8],
) -> KResult<Vec<u8>> {
    let name = algorithm.ssh_name(ca)?;
    let data = if matches!(
        algorithm,
        SshSignatureAlgorithm::EcdsaSha256
            | SshSignatureAlgorithm::EcdsaSha384
            | SshSignatureAlgorithm::EcdsaSha512
    ) {
        let parsed = EcdsaSig::from_der(signature)?;
        let mut encoded = Vec::new();
        put_mpint(&mut encoded, &parsed.r().to_vec())?;
        put_mpint(&mut encoded, &parsed.s().to_vec())?;
        encoded
    } else {
        signature.to_vec()
    };
    let mut encoded = Vec::new();
    put_string(&mut encoded, name.as_bytes())?;
    put_string(&mut encoded, &data)?;
    Ok(encoded)
}

fn verify_signature(
    key: &PKey<Public>,
    algorithm: SshSignatureAlgorithm,
    payload: &[u8],
    signature: &[u8],
) -> KResult<()> {
    let mut verifier = match algorithm {
        #[cfg(feature = "non-fips")]
        SshSignatureAlgorithm::Ed25519 => Verifier::new_without_digest(key)?,
        _ => Verifier::new(algorithm.digest(), key)?,
    };
    if !verifier.verify_oneshot(signature, payload)? {
        return Err(KmsError::ServerError(
            "SSH CA signature verification failed".to_owned(),
        ));
    }
    Ok(())
}

fn strip_algorithm(key_data: &[u8]) -> KResult<&[u8]> {
    let length = key_data
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| KmsError::InvalidRequest("malformed SSH public key".to_owned()))?;
    key_data
        .get(
            4_usize.checked_add(length).ok_or_else(|| {
                KmsError::InvalidRequest("malformed SSH public key length".to_owned())
            })?..,
        )
        .ok_or_else(|| KmsError::InvalidRequest("malformed SSH public key".to_owned()))
}

fn put_string(output: &mut Vec<u8>, value: &[u8]) -> KResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|e| KmsError::InvalidRequest(format!("SSH field exceeds maximum length: {e}")))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn put_mpint(output: &mut Vec<u8>, value: &[u8]) -> KResult<()> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let magnitude = value.get(first_nonzero..).ok_or_else(|| {
        KmsError::InvalidRequest("invalid SSH multiple-precision integer".to_owned())
    })?;
    let needs_sign_byte = magnitude.first().is_some_and(|byte| byte & 0x80 != 0);
    let length = magnitude
        .len()
        .checked_add(usize::from(needs_sign_byte))
        .ok_or_else(|| KmsError::InvalidRequest("SSH integer length overflow".to_owned()))?;
    let length = u32::try_from(length).map_err(|e| {
        KmsError::InvalidRequest(format!("SSH integer exceeds maximum length: {e}"))
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    if needs_sign_byte {
        output.push(0);
    }
    output.extend_from_slice(magnitude);
    Ok(())
}

pub(crate) fn validate_subject_algorithm(public_key: &PublicKey) -> KResult<()> {
    match public_key.algorithm() {
        Algorithm::Rsa { .. } => {
            let modulus_bits = public_key
                .key_data()
                .rsa()
                .and_then(|rsa| rsa.n.as_positive_bytes())
                .and_then(|bytes| {
                    let first = bytes.first()?;
                    Some(bytes.len() * 8 - usize::try_from(first.leading_zeros()).ok()?)
                })
                .unwrap_or(0);
            if modulus_bits < 2048 {
                return Err(KmsError::InvalidRequest(
                    "SSH subject RSA public key must be at least 2048 bits".to_owned(),
                ));
            }
            Ok(())
        }
        Algorithm::Ecdsa { .. } => Ok(()),
        #[cfg(feature = "non-fips")]
        Algorithm::Ed25519 => Ok(()),
        _ => Err(KmsError::InvalidRequest(
            "SSH subject public-key algorithm is not supported".to_owned(),
        )),
    }
}

pub(crate) fn validate_ca_key_algorithm(key: &PKey<Private>) -> KResult<()> {
    match key.id() {
        Id::RSA if key.rsa()?.n().num_bits() >= 2048 => Ok(()),
        Id::EC => {
            SshSignatureAlgorithm::from_public_key(&PKey::public_key_from_der(
                &key.public_key_to_der()?,
            )?)?;
            Ok(())
        }
        #[cfg(feature = "non-fips")]
        Id::ED25519 => Ok(()),
        _ => Err(KmsError::NotSupported(
            "SSH CA key must be RSA-2048+, NIST ECDSA, or Ed25519 in non-FIPS mode".to_owned(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Test assertions are the failure signal; fallible setup still propagates.
mod tests {
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        sign::Signer,
    };
    use ssh_key::{Certificate, PublicKey};

    use super::{
        CertificateTbs, SshSignatureAlgorithm, build_certificate_tbs, finish_certificate,
        open_ssh_public_key, verify_signature,
    };

    #[test]
    fn weak_rsa_subject_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let weak = PKey::from_rsa(Rsa::generate(1024)?)?;
        let weak_public = PKey::public_key_from_der(&weak.public_key_to_der()?)?;
        let subject = PublicKey::from_openssh(&open_ssh_public_key(&weak_public)?)?;
        assert!(super::validate_subject_algorithm(&subject).is_err());
        Ok(())
    }

    #[test]
    fn rsa_certificate_round_trips_as_openssh() -> Result<(), Box<dyn std::error::Error>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let private = PKey::from_rsa(Rsa::generate(2048)?)?;
        let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
        let ssh_public = open_ssh_public_key(&public)?;
        let ca = PublicKey::from_openssh(&ssh_public)?;
        let subject = PublicKey::from_openssh(&ssh_public)?;
        let principals = vec!["alice".to_owned()];
        let tbs = build_certificate_tbs(&CertificateTbs {
            subject: &subject,
            ca: &ca,
            role: "developers",
            principals: &principals,
            valid_after: 1,
            valid_before: 901,
            serial: 7,
            nonce: &[3; 16],
        })?;
        let mut signer = Signer::new(MessageDigest::sha256(), &private)?;
        signer.update(&tbs)?;
        let signature = signer.sign_to_vec()?;
        let algorithm = SshSignatureAlgorithm::from_public_key(&public)?;
        verify_signature(&public, algorithm, &tbs, &signature)?;
        let certificate = finish_certificate(&tbs, &ca, algorithm, &signature)?;
        assert!(certificate.starts_with("ssh-rsa-cert-v01@openssh.com "));
        let parsed = Certificate::from_openssh(&certificate)?;
        assert_eq!(parsed.to_openssh()?, certificate);
        Ok(())
    }

    #[test]
    fn ecdsa_certificate_encodes_mpint_signature_components()
    -> Result<(), Box<dyn std::error::Error>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let private = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
        let ssh_public = open_ssh_public_key(&public)?;
        let ca = PublicKey::from_openssh(&ssh_public)?;
        let subject = PublicKey::from_openssh(&ssh_public)?;
        let principals = vec!["alice".to_owned()];
        let tbs = build_certificate_tbs(&CertificateTbs {
            subject: &subject,
            ca: &ca,
            role: "developers",
            principals: &principals,
            valid_after: 1,
            valid_before: 901,
            serial: 8,
            nonce: &[4; 16],
        })?;
        let mut signer = Signer::new(MessageDigest::sha256(), &private)?;
        signer.update(&tbs)?;
        let signature = signer.sign_to_vec()?;
        let algorithm = SshSignatureAlgorithm::from_public_key(&public)?;
        verify_signature(&public, algorithm, &tbs, &signature)?;
        let certificate = finish_certificate(&tbs, &ca, algorithm, &signature)?;
        assert!(certificate.starts_with("ecdsa-sha2-nistp256-cert-v01@openssh.com "));
        let parsed = Certificate::from_openssh(&certificate)?;
        assert_eq!(parsed.to_openssh()?, certificate);
        Ok(())
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn ed25519_certificate_round_trips_as_openssh() -> Result<(), Box<dyn std::error::Error>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let private = PKey::generate_ed25519()?;
        let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
        let ssh_public = open_ssh_public_key(&public)?;
        let ca = PublicKey::from_openssh(&ssh_public)?;
        let subject = PublicKey::from_openssh(&ssh_public)?;
        let principals = ["alice".to_owned()];
        let tbs = build_certificate_tbs(&CertificateTbs {
            subject: &subject,
            ca: &ca,
            role: "developers",
            principals: &principals,
            valid_after: 1,
            valid_before: 901,
            serial: 9,
            nonce: &[5; 16],
        })?;
        let mut signer = Signer::new_without_digest(&private)?;
        let signature = signer.sign_oneshot_to_vec(&tbs)?;
        let algorithm = SshSignatureAlgorithm::from_public_key(&public)?;
        verify_signature(&public, algorithm, &tbs, &signature)?;
        let certificate = finish_certificate(&tbs, &ca, algorithm, &signature)?;
        assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let parsed = Certificate::from_openssh(&certificate)?;
        assert_eq!(parsed.to_openssh()?, certificate);
        Ok(())
    }
}
