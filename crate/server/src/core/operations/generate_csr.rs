//! PKCS#10 certificate signing request (CSR) generation for a private key held by the KMS.
//!
//! The private key never leaves the server: keys stored in an HSM sign through the crypto
//! oracle (the HSM key may be non-extractable), database keys sign in process.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, State},
        kmip_2_1::{
            KmipOperation, extra::tagging::SYSTEM_TAG_PUBLIC_KEY, kmip_objects::ObjectType,
            kmip_types::OperationEnumeration,
        },
    },
    cosmian_kms_crypto::openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey},
    x509::{X509Name, X509NameBuilder, X509Req, X509ReqBuilder},
};

use super::dispatch::check_role_permission;
use crate::{
    core::{
        KMS, ObjectHandle,
        certificate::oracle_signing::{
            OracleSigningKey, assemble_csr, oracle_sign, placeholder_signing_key, prepare_csr,
        },
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

/// Split `subject` on commas not preceded by a backslash; `\,` and `\\` are unescaped.
fn split_unescaped(subject: &str) -> Vec<String> {
    let mut parts = vec![];
    let mut current = String::new();
    let mut chars = subject.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ',' => parts.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    parts.push(current);
    parts
}

/// Parse `C=FR, O=Acme\, SA, OU=PKI, OU=Sub, CN=Sub CA` into an X.509 name, keeping the RDNs in
/// input order and allowing repeated attributes. Any OpenSSL short or long attribute name is
/// accepted (`organizationIdentifier`, `serialNumber`, ...).
fn parse_distinguished_name(subject: &str) -> KResult<X509Name> {
    let mut builder = X509NameBuilder::new()?;
    for part in split_unescaped(subject) {
        let invalid = |reason: &str| {
            KmsError::InvalidRequest(format!(
                "CSR generation: invalid subject name component '{part}': {reason}"
            ))
        };
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| invalid("expected <attribute>=<value>"))?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() || value.is_empty() {
            return Err(invalid("empty attribute or value"));
        }
        // OpenSSL takes C strings: an interior NUL would panic in the binding
        if key.contains('\0') || value.contains('\0') {
            return Err(invalid("NUL characters are not allowed"));
        }
        // `append_entry_by_text` picks the narrowest valid string type, but only for ASCII
        let result = if value.is_ascii() {
            builder.append_entry_by_text(key, value)
        } else {
            builder.append_entry_by_text_with_type(key, value, openssl::asn1::Asn1Type::UTF8STRING)
        };
        result.map_err(|e| invalid(&e.to_string()))?;
    }
    Ok(builder.build())
}

/// Generate a PKCS#10 CSR for the private key `private_key_id`.
///
/// Signs with the exact key requested: HSM keys through the crypto oracle, database keys in
/// process. Only the `Sign` permission is required on the private key, never `Get`.
pub(crate) async fn generate_csr(
    kms: &KMS,
    private_key_id: &str,
    subject_name: &str,
    user: &UserId,
) -> KResult<X509Req> {
    if subject_name.trim().is_empty() {
        kms_bail!(KmsError::InvalidRequest(
            "CSR generation: subject_name must not be empty".to_owned()
        ));
    }
    let name = parse_distinguished_name(subject_name)?;

    // REST handlers skip the KMIP dispatch gate: apply the role check here
    check_role_permission(
        kms,
        user.as_str(),
        OperationEnumeration::Sign,
        &kms.params.crypto_officer,
    )
    .await?;
    let sk = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(private_key_id),
        KmipOperation::Sign,
        kms,
        user,
    ))
    .await?;

    // The sensitive-HSM RSA stub is SymmetricKey-shaped but carries `PrivateKey` in its attributes
    if sk.object().object_type() != ObjectType::PrivateKey
        && sk.attributes().object_type != Some(ObjectType::PrivateKey)
    {
        kms_bail!(KmsError::InvalidRequest(format!(
            "CSR generation: '{private_key_id}' is not a private key"
        )));
    }
    // KMIP §4.57: only Active keys sign (as the KMIP Sign operation and Certify require)
    let state = sk.effective_state();
    if state != State::Active {
        kms_bail!(KmsError::InvalidRequest(format!(
            "CSR generation: private key '{}' is in state '{state}' — only Active keys may sign",
            sk.id()
        )));
    }
    if !sk.has_usage_mask(CryptographicUsageMask::Sign, true) {
        kms_bail!(KmsError::InvalidRequest(format!(
            "CSR generation: the usage mask of private key '{}' does not allow Sign",
            sk.id()
        )));
    }
    let is_hsm = ObjectHandle::from(sk.id()).is_hsm();
    if is_hsm && sk.attributes().sensitive != Some(true) {
        kms_bail!(KmsError::InvalidRequest(format!(
            "CSR generation: HSM key '{}' is extractable; create it with --sensitive",
            sk.id()
        )));
    }

    // Never follow the `PublicKeyLink` of the private key: it is user-controlled and would let a
    // caller probe objects they have no grant on. Database keys use the public key derived from
    // the private key; HSM objects carry no KMIP links, their public key is `<sk>_pk`.
    let (csr, public_key) = if is_hsm {
        let pk_id = format!("{}{SYSTEM_TAG_PUBLIC_KEY}", sk.id());
        let pk_owm = kms
            .database
            .retrieve_object_arc(&pk_id)
            .await
            .with_context(|| format!("CSR generation: retrieving public key '{pk_id}'"))?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("CSR generation: public key '{pk_id}' not found"))
            })?;
        let pk_object =
            Box::pin(kms.get_unwrapped(pk_owm.id(), pk_owm.object(), pk_owm.owner_id()))
                .await
                .with_context(|| format!("CSR generation: retrieving public key '{pk_id}'"))?;
        let public_key = kmip_public_key_to_openssl(&pk_object)?;
        let key = OracleSigningKey::for_hsm_uid(sk.id(), public_key.clone())?.ok_or_else(|| {
            KmsError::ServerError(format!("CSR generation: '{}' is not an HSM key", sk.id()))
        })?;
        let draft = {
            let mut builder = X509ReqBuilder::new()?;
            builder.set_version(0)?;
            builder.set_subject_name(&name)?;
            builder.set_pubkey(&public_key)?;
            let placeholder = placeholder_signing_key()?;
            builder.sign(&placeholder, MessageDigest::sha256())?;
            builder.build()
        };
        let (req, tbs) = prepare_csr(&draft, key.algorithm)?;
        let signature = Box::pin(oracle_sign(kms, &key, &tbs)).await?;
        (assemble_csr(req, &signature)?, public_key)
    } else {
        let unwrapped = Box::pin(kms.get_unwrapped(sk.id(), sk.object(), user)).await?;
        let private_key = kmip_private_key_to_openssl(&unwrapped)?;
        let public_key = PKey::public_key_from_der(&private_key.public_key_to_der()?)?;
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;
        builder.set_subject_name(&name)?;
        builder.set_pubkey(&public_key)?;
        // RSA and EC need an explicit digest; EdDSA and PQC algorithms hash internally.
        let digest = match private_key.id() {
            Id::RSA | Id::EC => MessageDigest::sha256(),
            _ => MessageDigest::null(),
        };
        // KEM keys (X25519, ML-KEM, ...) cannot sign: a client error, not a server failure
        builder
            .sign(&private_key, digest)
            .map_err(|_openssl_error| {
                KmsError::InvalidRequest(format!(
                    "CSR generation: a {:?} key cannot sign a CSR",
                    private_key.id()
                ))
            })?;
        (builder.build(), public_key)
    };

    if !csr.verify(&public_key)? {
        kms_bail!(KmsError::ServerError(format!(
            "CSR generation: the signature does not verify with the public key of '{}'",
            sk.id()
        )));
    }
    Ok(csr)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entries(name: &X509Name) -> Vec<(String, String)> {
        name.entries()
            .map(|e| {
                (
                    e.object().nid().long_name().unwrap().to_owned(),
                    String::from_utf8(e.data().as_slice().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn subject_keeps_order_repeats_escapes_and_rare_attributes() {
        let name = parse_distinguished_name(
            r"C=FR, O=Acme\, SA, OU=PKI, OU=Sub, organizationIdentifier=VATFR-123, CN=Acme Sub CA",
        )
        .unwrap();
        assert_eq!(
            entries(&name),
            vec![
                ("countryName".to_owned(), "FR".to_owned()),
                ("organizationName".to_owned(), "Acme, SA".to_owned()),
                ("organizationalUnitName".to_owned(), "PKI".to_owned()),
                ("organizationalUnitName".to_owned(), "Sub".to_owned()),
                ("organizationIdentifier".to_owned(), "VATFR-123".to_owned()),
                ("commonName".to_owned(), "Acme Sub CA".to_owned()),
            ]
        );
        assert_eq!(
            parse_distinguished_name("CN=x").unwrap().entries().count(),
            1
        );
    }

    #[test]
    fn subject_rejects_malformed_components() {
        for bad in ["CN=", "=x", "CN", "bogusAttr=x", "CN=a\0b", "C\0N=a"] {
            assert!(
                matches!(
                    parse_distinguished_name(bad),
                    Err(KmsError::InvalidRequest(_))
                ),
                "{bad}"
            );
        }
    }
}
