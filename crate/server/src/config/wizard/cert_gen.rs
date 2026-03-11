//! Self-signed PKI generator for the KMS configuration wizard.
//!
//! Generates a self-signed CA certificate, a server certificate, and a client
//! certificate issued by that CA.  All keys and certificates are written as PEM
//! files to a chosen output directory.
//!
//! Key sizes: RSA-4096 for the CA, RSA-4096 for leaf certificates (FIPS-safe).

#![allow(unreachable_pub, clippy::print_stdout)]

use std::path::{Path, PathBuf};

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509Builder, X509NameBuilder, X509Req,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};

use crate::{error::KmsError, result::KResult};

/// Paths to all generated certificate/key PEM files.
pub struct CertPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    #[allow(dead_code)]
    pub client_key: PathBuf,
}

/// Options for the self-signed PKI generator.
pub struct CertGenOptions {
    /// Directory where PEM files will be written.
    pub output_dir: PathBuf,
    /// Common Name for the CA certificate.
    pub ca_cn: String,
    /// Common Name for the server leaf certificate.
    pub server_cn: String,
    /// Common Name for the client leaf certificate.
    pub client_cn: String,
    /// Validity (days) for the CA certificate.
    pub ca_validity_days: u32,
    /// Validity (days) for the server leaf certificate.
    pub server_validity_days: u32,
    /// Validity (days) for the client leaf certificate.
    pub client_validity_days: u32,
}

impl Default for CertGenOptions {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("/etc/cosmian"),
            ca_cn: "Cosmian KMS CA".to_owned(),
            server_cn: "Cosmian KMS Server".to_owned(),
            client_cn: "Cosmian KMS Client".to_owned(),
            ca_validity_days: 3650,
            server_validity_days: 365,
            client_validity_days: 365,
        }
    }
}

/// Generate a random serial number for a certificate.
fn random_serial() -> KResult<openssl::asn1::Asn1Integer> {
    let mut serial = BigNum::new().map_err(|e| KmsError::ServerError(e.to_string()))?;
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    serial
        .to_asn1_integer()
        .map_err(|e| KmsError::ServerError(e.to_string()))
}

/// Generate an RSA private key and return it as a `PKey<Private>`.
fn gen_rsa_key(bits: u32) -> KResult<PKey<Private>> {
    let rsa = Rsa::generate(bits).map_err(|e| KmsError::ServerError(e.to_string()))?;
    PKey::from_rsa(rsa).map_err(|e| KmsError::ServerError(e.to_string()))
}

/// Write `content` (PEM bytes) to `dir/filename`, creating `dir` if needed.
fn write_pem(dir: &Path, filename: &str, content: &[u8]) -> KResult<PathBuf> {
    std::fs::create_dir_all(dir).map_err(|e| {
        KmsError::ServerError(format!("Cannot create directory {}: {e}", dir.display()))
    })?;
    let path = dir.join(filename);
    std::fs::write(&path, content)
        .map_err(|e| KmsError::ServerError(format!("Cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// Build a self-signed CA certificate.
fn build_ca_cert(key: &PKey<Private>, opts: &CertGenOptions) -> KResult<X509> {
    let mut name = X509NameBuilder::new().map_err(|e| KmsError::ServerError(e.to_string()))?;
    name.append_entry_by_text("CN", &opts.ca_cn)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let name = name.build();

    let mut builder = X509Builder::new().map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_version(2)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_subject_name(&name)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_pubkey(key)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let not_before =
        Asn1Time::days_from_now(0).map_err(|e| KmsError::ServerError(e.to_string()))?;
    let not_after = Asn1Time::days_from_now(opts.ca_validity_days)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    // Extensions
    let basic_constraints = BasicConstraints::new()
        .critical()
        .ca()
        .build()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .append_extension(basic_constraints)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .append_extension(key_usage)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .append_extension(ski)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    builder
        .sign(key, MessageDigest::sha256())
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    Ok(builder.build())
}

/// Build a CSR (used to create leaf certificates).
fn build_csr(key: &PKey<Private>, cn: &str) -> KResult<X509Req> {
    let mut name = X509NameBuilder::new().map_err(|e| KmsError::ServerError(e.to_string()))?;
    name.append_entry_by_text("CN", cn)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let name = name.build();

    let mut req = X509Req::builder().map_err(|e| KmsError::ServerError(e.to_string()))?;
    req.set_version(0)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    req.set_subject_name(&name)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    req.set_pubkey(key)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    req.sign(key, MessageDigest::sha256())
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    Ok(req.build())
}

/// Issue a leaf certificate (server or client) signed by `ca_cert`/`ca_key`.
fn issue_leaf_cert(
    csr: &X509Req,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    validity_days: u32,
) -> KResult<X509> {
    let mut builder = X509Builder::new().map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_version(2)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let serial = random_serial()?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_subject_name(csr.subject_name())
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_issuer_name(ca_cert.subject_name())
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let pubkey = csr
        .public_key()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_pubkey(&pubkey)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let not_before =
        Asn1Time::days_from_now(0).map_err(|e| KmsError::ServerError(e.to_string()))?;
    let not_after =
        Asn1Time::days_from_now(validity_days).map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let basic_constraints = BasicConstraints::new()
        .build()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    builder
        .append_extension(basic_constraints)
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    builder
        .sign(ca_key, MessageDigest::sha256())
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    Ok(builder.build())
}

/// Generate a complete self-signed PKI (CA + server cert + client cert) and write PEM files.
///
/// Returns [`CertPaths`] with the paths of the generated files.
pub fn generate_self_signed_pki(opts: &CertGenOptions) -> KResult<CertPaths> {
    println!("  Generating CA key (RSA-4096)…");
    let ca_key = gen_rsa_key(4096)?;
    let ca_cert = build_ca_cert(&ca_key, opts)?;
    let ca_cert_pem = ca_cert
        .to_pem()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let ca_cert_path = write_pem(&opts.output_dir, "ca.crt", &ca_cert_pem)?;

    println!("  Generating server key (RSA-4096)…");
    let server_key = gen_rsa_key(4096)?;
    let server_csr = build_csr(&server_key, &opts.server_cn)?;
    let server_cert = issue_leaf_cert(&server_csr, &ca_cert, &ca_key, opts.server_validity_days)?;
    let server_cert_pem = server_cert
        .to_pem()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let server_key_pem = server_key
        .private_key_to_pem_pkcs8()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let server_cert_path = write_pem(&opts.output_dir, "server.crt", &server_cert_pem)?;
    let server_key_path = write_pem(&opts.output_dir, "server.key", &server_key_pem)?;

    println!("  Generating client key (RSA-4096)…");
    let client_key = gen_rsa_key(4096)?;
    let client_csr = build_csr(&client_key, &opts.client_cn)?;
    let client_cert = issue_leaf_cert(&client_csr, &ca_cert, &ca_key, opts.client_validity_days)?;
    let client_cert_pem = client_cert
        .to_pem()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let client_key_pem = client_key
        .private_key_to_pem_pkcs8()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    let client_cert_path = write_pem(&opts.output_dir, "client.crt", &client_cert_pem)?;
    let client_key_path = write_pem(&opts.output_dir, "client.key", &client_key_pem)?;

    println!("  Certificates written to {}", opts.output_dir.display());
    println!("    CA cert     : {}", ca_cert_path.display());
    println!("    Server cert : {}", server_cert_path.display());
    println!("    Server key  : {}", server_key_path.display());
    println!("    Client cert : {}", client_cert_path.display());

    Ok(CertPaths {
        ca_cert: ca_cert_path,
        server_cert: server_cert_path,
        server_key: server_key_path,
        client_cert: client_cert_path,
        client_key: client_key_path,
    })
}
