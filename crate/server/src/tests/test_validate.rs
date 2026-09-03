#![allow(clippy::unwrap_used, clippy::unwrap_in_result)]

// ── PQC X.509 Certificate Chain Validation Tests (RFC 9881 / RFC 9935) ────────────
//
// These tests validate PQC certificate chains using the KMIP Validate operation.
// All functions are cfg(feature = "non-fips") because PQC algorithms are not FIPS-approved.
//
// RFC references:
//   RFC 9881 — ML-DSA in X.509: keyUsage MUST be critical, MUST include digitalSignature
//   RFC 9935 — ML-KEM in X.509: keyUsage MUST be critical, MUST be keyEncipherment ONLY
//   draft-ietf-lamps-x509-slh-dsa — same keyUsage as ML-DSA
//
// Chain topologies tested:
//   1-level : self-signed root only
//   2-level : root CA → leaf
//   3-level : root CA → intermediate CA → leaf
//
// Failure / edge cases tested:
//   - ML-KEM self-signed is always rejected (KEM cannot sign)
//   - Certificate chain with a future validity_time beyond expiry → invalid
//   - Missing intermediate in 3-level chain → invalid
//   - Missing root in 3-level chain → invalid
//   - Empty chain → invalid
//   - Leaf signed by a different CA than the one provided → invalid
//   - Certificates supplied out-of-order → sorted internally, still valid
//   - All three ML-DSA variants (44, 65, 87) as roots → all valid
//   - All three ML-KEM variants (512, 768, 1024) as CA-issued leaves → all valid
#[cfg(feature = "non-fips")]
mod pqc_validate_tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, Object},
        kmip_operations::{Certify, Get, GetAttributes, Validate},
        kmip_types::{
            CertificateAttributes, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier, ValidityIndicator, VendorAttribute, VendorAttributeValue,
        },
    };
    use x509_parser::prelude::{FromDer, X509Certificate};

    use crate::{
        config::ServerParams, core::KMS, error::KmsError, middlewares::UserId, result::KResult,
        tests::test_utils::https_clap_config,
    };

    // ── Extension config constants ────────────────────────────────────────────────

    /// Extension config for self-signed ROOT CA certificates.
    ///
    /// `authorityKeyIdentifier` is intentionally absent: when OpenSSL builds a
    /// self-signed certificate there is no issuer cert in the X.509 builder
    /// context.  `v2i_AUTHORITY_KEYID` therefore cannot resolve `keyid:always`
    /// and returns an error.  RFC 5280 §4.2.1.1 explicitly allows AKI to be
    /// omitted for self-signed (root) certificates.
    ///
    /// `sort_certificates` detects roots either by `SKI == AKI` (classical PKI)
    /// or by `issuer_name == subject_name` (RFC 5280 self-signed detection),
    /// so this extension is sufficient for chain sorting to work.
    const PQC_ROOT_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
";

    /// Extension config for INTERMEDIATE CA certificates (CA-issued).
    ///
    /// The issuer cert is available in the builder context at this point so
    /// `authorityKeyIdentifier=keyid:always,issuer` can copy the issuer's SKI
    /// into the AKI field, enabling `sort_certificates` to link the chain.
    const PQC_SUBCA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:TRUE
";

    /// Extension config for LEAF certificates (CA-issued, not a CA themselves).
    ///
    /// `keyUsage` is intentionally absent: `build_and_sign_certificate` adds the
    /// RFC-mandated critical keyUsage extension for PQC subject keys automatically
    /// via `pqc_rfc_key_usage()`.  Adding it here would create a duplicate OID.
    ///
    /// No `crlDistributionPoints` so CRL fetching is skipped in tests.
    const PQC_LEAF_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
";

    // ── Infrastructure helpers ────────────────────────────────────────────────────

    /// Spin up a fresh, empty in-process KMS instance with an `SQLite` backend.
    /// No network access is required.
    async fn make_kms() -> KResult<Arc<KMS>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let clap_config = https_clap_config();
        let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
        Ok(kms)
    }

    /// Issue a PQC certificate via the KMIP `Certify` operation.
    ///
    /// When `issuer_cert_id` and `issuer_sk_id` are `None` the certificate is
    /// self-signed (root CA mode).  Otherwise it is signed by the given issuer.
    ///
    /// `extension` is the OpenSSL `[v3_ca]` section text to embed in the cert.
    ///
    /// Returns `(cert_id, sk_id)` — the unique identifiers of the newly created
    /// certificate and its associated private key.
    async fn pqc_certify(
        kms: &Arc<KMS>,
        owner: &str,
        algo: CryptographicAlgorithm,
        cn: &str,
        issuer_cert_id: Option<&str>,
        issuer_sk_id: Option<&str>,
        extension: &[u8],
    ) -> KResult<(String, String)> {
        let subject_name = format!("C=FR, ST=IdF, L=Paris, O=PQCTest, CN={cn}");

        // Build optional issuer links
        let mut links: Vec<Link> = Vec::new();
        if let Some(id) = issuer_cert_id {
            links.push(Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
            });
        }
        if let Some(id) = issuer_sk_id {
            links.push(Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
            });
        }

        let attributes = Attributes {
            cryptographic_algorithm: Some(algo),
            certificate_attributes: Some(CertificateAttributes::parse_subject_line(&subject_name)?),
            link: if links.is_empty() { None } else { Some(links) },
            vendor_attributes: Some(vec![VendorAttribute {
                vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
                attribute_value: VendorAttributeValue::ByteString(extension.to_vec()),
            }]),
            ..Attributes::default()
        };

        let certify_req = Certify {
            attributes: Some(attributes),
            ..Certify::default()
        };

        let cert_id = kms
            .certify(certify_req, &UserId::from(owner))
            .await?
            .unique_identifier
            .to_string();

        // Retrieve the private key ID stored as PrivateKeyLink on the certificate.
        let attrs = kms
            .get_attributes(GetAttributes::from(cert_id.clone()), &UserId::from(owner))
            .await?
            .attributes;
        let sk_id = attrs
            .get_link(LinkType::PrivateKeyLink)
            .ok_or_else(|| {
                KmsError::ServerError("Certificate missing PrivateKeyLink attribute".to_owned())
            })?
            .to_string();

        Ok((cert_id, sk_id))
    }

    // ── Validate helpers ─────────────────────────────────────────────────────────

    /// Validate a chain expressed as a slice of cert IDs. Asserts `Valid`.
    async fn assert_chain_valid(kms: &Arc<KMS>, owner: &str, cert_ids: &[&str]) {
        let unique_identifiers = Some(
            cert_ids
                .iter()
                .map(|id| UniqueIdentifier::TextString((*id).to_owned()))
                .collect(),
        );
        let req = Validate {
            certificate: None,
            unique_identifier: unique_identifiers,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &UserId::from(owner))).await;
        assert!(
            matches!(
                res,
                Ok(ref r) if r.validity_indicator == ValidityIndicator::Valid
            ),
            "expected Valid, got: {res:?}"
        );
    }

    /// Validate a chain with an explicit `validity_time`. Expects an error (invalid / expired).
    async fn assert_chain_invalid_at(
        kms: &Arc<KMS>,
        owner: &str,
        cert_ids: &[&str],
        validity_time: &str,
    ) {
        let unique_identifiers = Some(
            cert_ids
                .iter()
                .map(|id| UniqueIdentifier::TextString((*id).to_owned()))
                .collect(),
        );
        let req = Validate {
            certificate: None,
            unique_identifier: unique_identifiers,
            validity_time: Some(validity_time.to_owned()),
        };
        let res = Box::pin(kms.validate(req, &UserId::from(owner))).await;
        assert!(
            res.is_err(),
            "expected an error (expired/invalid chain), got: {res:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Happy-path tests — 1-level (self-signed root)
    // ═══════════════════════════════════════════════════════════════════════════

    /// ML-DSA-44 self-signed root certificate validates as a single-cert chain.
    #[tokio::test]
    async fn test_validate_pqc_ml_dsa44_self_signed() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");
        let (cert_id, _sk_id) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        Ok(())
    }

    /// ML-DSA-65 self-signed root certificate validates.
    #[tokio::test]
    async fn test_validate_pqc_ml_dsa65_self_signed() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");
        let (cert_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Root",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        Ok(())
    }

    /// ML-DSA-87 self-signed root certificate validates.
    #[tokio::test]
    async fn test_validate_pqc_ml_dsa87_self_signed() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");
        let (cert_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Root",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        Ok(())
    }

    /// SLH-DSA-SHA2-128s self-signed root certificate validates.
    #[tokio::test]
    async fn test_validate_pqc_slhdsa_sha2_128s_self_signed() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");
        let (cert_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::SLHDSA_SHA2_128s,
            "SLH-DSA-SHA2-128s Root",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Happy-path tests — 2-level chain (root → leaf)
    // ═══════════════════════════════════════════════════════════════════════════

    /// ML-DSA-44 root → ML-DSA-44 leaf: basic 2-level homogeneous chain.
    #[tokio::test]
    async fn test_validate_pqc_2level_mldsa44_root_mldsa44_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        // Root CA (self-signed)
        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;

        // Leaf (signed by root)
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// ML-DSA-44 root → ML-DSA-87 leaf: cross-variant 2-level chain.
    #[tokio::test]
    async fn test_validate_pqc_2level_mldsa44_root_mldsa87_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// RFC 9935 — ML-DSA-44 root → ML-KEM-512 leaf.
    /// ML-KEM certificates have keyUsage=critical,keyEncipherment per RFC 9935.
    #[tokio::test]
    async fn test_validate_pqc_2level_mldsa44_root_mlkem512_leaf_rfc9935() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLKEM_512,
            "ML-KEM-512 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// RFC 9935 — ML-DSA-65 root → ML-KEM-768 leaf.
    #[tokio::test]
    async fn test_validate_pqc_2level_mldsa65_root_mlkem768_leaf_rfc9935() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLKEM_768,
            "ML-KEM-768 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// RFC 9935 — ML-DSA-87 root → ML-KEM-1024 leaf.
    #[tokio::test]
    async fn test_validate_pqc_2level_mldsa87_root_mlkem1024_leaf_rfc9935() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLKEM_1024,
            "ML-KEM-1024 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// Cross-family: SLH-DSA-SHA2-128s root → ML-DSA-44 leaf.
    #[tokio::test]
    async fn test_validate_pqc_2level_slhdsa_root_mldsa44_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::SLHDSA_SHA2_128s,
            "SLH-DSA Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// Cross-family: SLH-DSA-SHA2-128s root → ML-KEM-512 leaf (RFC 9935).
    #[tokio::test]
    async fn test_validate_pqc_2level_slhdsa_root_mlkem512_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::SLHDSA_SHA2_128s,
            "SLH-DSA Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLKEM_512,
            "ML-KEM-512 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Happy-path tests — 3-level chain (root → intermediate → leaf)
    // ═══════════════════════════════════════════════════════════════════════════

    /// All-ML-DSA 3-level chain:
    ///   ML-DSA-44 root → ML-DSA-65 intermediate → ML-DSA-87 leaf
    ///
    /// Each level uses a distinct variant to maximise coverage of the OID table
    /// and the `sort_certificates` path-building logic.
    #[tokio::test]
    async fn test_validate_pqc_3level_all_mldsa_variants() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        // Root CA (self-signed ML-DSA-44)
        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;

        // Intermediate CA (ML-DSA-65, signed by root)
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;

        // Leaf (ML-DSA-87, signed by intermediate)
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &int_id, &leaf_id]).await;
        Ok(())
    }

    /// 3-level chain with ML-KEM leaf (RFC 9935):
    ///   ML-DSA-65 root → ML-DSA-65 intermediate → ML-KEM-768 leaf
    #[tokio::test]
    async fn test_validate_pqc_3level_mldsa65_chain_mlkem768_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLKEM_768,
            "ML-KEM-768 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &int_id, &leaf_id]).await;
        Ok(())
    }

    /// 3-level chain with SLH-DSA root:
    ///   SLH-DSA-SHA2-128s root → ML-DSA-44 intermediate → ML-DSA-65 leaf
    #[tokio::test]
    async fn test_validate_pqc_3level_slhdsa_root_mldsa_chain() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::SLHDSA_SHA2_128s,
            "SLH-DSA Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &int_id, &leaf_id]).await;
        Ok(())
    }

    /// Chain supplied in reverse order (leaf, intermediate, root) must still be
    /// sorted correctly and validate successfully.
    #[tokio::test]
    async fn test_validate_pqc_3level_unordered_input_still_valid() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Supply in reverse order — sort_certificates must handle this.
        assert_chain_valid(&kms, &owner, &[&leaf_id, &int_id, &root_id]).await;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Failure tests — things that must NOT validate
    // ═══════════════════════════════════════════════════════════════════════════

    /// ML-KEM-512 cannot be used as a self-signed certificate because KEM keys
    /// cannot produce digital signatures.  The Certify operation must be rejected
    /// before a certificate is created.
    #[tokio::test]
    async fn test_validate_pqc_ml_kem_self_signed_is_rejected_at_certify() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let attributes = {
            let subject_name = "C=FR, ST=IdF, L=Paris, O=PQCTest, CN=ML-KEM Self-Signed";

            Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    subject_name,
                )?),
                vendor_attributes: Some(vec![VendorAttribute {
                    vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                    attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
                    attribute_value: VendorAttributeValue::ByteString(PQC_ROOT_EXT.to_vec()),
                }]),
                ..Attributes::default()
            }
        };
        let certify_req = Certify {
            attributes: Some(attributes),
            ..Certify::default()
        };

        let result = kms.certify(certify_req, &owner).await;
        assert!(
            result.is_err(),
            "ML-KEM self-signed certificate creation must be rejected, but it succeeded"
        );
        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err_msg.contains("kem") || err_msg.contains("sign") || err_msg.contains("encapsul"),
            "error message should mention KEM/sign/encapsulation, got: {err_msg}"
        );
        Ok(())
    }

    /// ML-KEM-768 cannot self-sign either — covers a second KEM variant.
    #[tokio::test]
    async fn test_validate_pqc_ml_kem768_self_signed_is_rejected_at_certify() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
            certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                "C=FR, O=PQCTest, CN=ML-KEM-768 Self-Signed",
            )?),
            ..Attributes::default()
        };
        let result = kms
            .certify(
                Certify {
                    attributes: Some(attrs),
                    ..Certify::default()
                },
                &owner,
            )
            .await;
        assert!(result.is_err(), "ML-KEM-768 self-signed must be rejected");
        Ok(())
    }

    /// A valid 2-level chain that is asked to be valid far in the future (year 4804)
    /// must be rejected because the certificates will have expired by then.
    #[tokio::test]
    async fn test_validate_pqc_2level_chain_future_validity_time_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Chain must be valid today.
        assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;

        // Year 4804 is well beyond the 365-day default validity.
        assert_chain_invalid_at(&kms, &owner, &[&root_id, &leaf_id], "4804152030Z").await;
        Ok(())
    }

    /// A valid 3-level chain checked at a far-future date must fail.
    #[tokio::test]
    async fn test_validate_pqc_3level_chain_future_validity_time_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        assert_chain_valid(&kms, &owner, &[&root_id, &int_id, &leaf_id]).await;
        assert_chain_invalid_at(&kms, &owner, &[&root_id, &int_id, &leaf_id], "4804152030Z").await;
        Ok(())
    }

    /// Providing root and leaf without the intermediate certificate must fail.
    /// `sort_certificates` or `verify_chain_signature` must detect the broken chain.
    #[tokio::test]
    async fn test_validate_pqc_3level_missing_intermediate_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Full chain is valid.
        assert_chain_valid(&kms, &owner, &[&root_id, &int_id, &leaf_id]).await;

        // Missing intermediate — must fail.
        let req = Validate {
            certificate: None,
            unique_identifier: Some(vec![
                UniqueIdentifier::TextString(root_id.clone()),
                UniqueIdentifier::TextString(leaf_id.clone()),
            ]),
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "missing intermediate must cause validation failure, got: {res:?}"
        );
        Ok(())
    }

    /// Providing intermediate and leaf without the root certificate must fail.
    #[tokio::test]
    async fn test_validate_pqc_3level_missing_root_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (int_id, int_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Intermediate CA",
            Some(&root_id),
            Some(&root_sk),
            PQC_SUBCA_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "ML-DSA-87 Leaf",
            Some(&int_id),
            Some(&int_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Missing root — must fail.
        let req = Validate {
            certificate: None,
            unique_identifier: Some(vec![
                UniqueIdentifier::TextString(int_id.clone()),
                UniqueIdentifier::TextString(leaf_id.clone()),
            ]),
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "missing root must cause validation failure, got: {res:?}"
        );
        Ok(())
    }

    /// Providing an empty identifier list must immediately return an error.
    #[tokio::test]
    async fn test_validate_pqc_empty_chain_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let req = Validate {
            certificate: None,
            unique_identifier: None,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "empty chain must return an error, got: {res:?}"
        );
        Ok(())
    }

    /// Providing a leaf certificate from chain-A together with the root of chain-B
    /// (a completely different CA) must fail chain signature verification.
    #[tokio::test]
    async fn test_validate_pqc_leaf_with_wrong_issuer_fails() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        // Chain A: ML-DSA-44 root A → ML-DSA-65 leaf A
        let (root_a_id, root_a_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "Root CA - A",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_a_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "Leaf - A",
            Some(&root_a_id),
            Some(&root_a_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Chain B: ML-DSA-87 root B (independent)
        let (root_b_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_87,
            "Root CA - B",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;

        // root_b + leaf_a: leaf_a was NOT signed by root_b — must fail.
        let req = Validate {
            certificate: None,
            unique_identifier: Some(vec![
                UniqueIdentifier::TextString(root_b_id.clone()),
                UniqueIdentifier::TextString(leaf_a_id.clone()),
            ]),
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "leaf from chain-A validated with root from chain-B must fail, got: {res:?}"
        );

        // Verify that the correct pairing still works.
        assert_chain_valid(&kms, &owner, &[&root_a_id, &leaf_a_id]).await;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Edge-case / coverage tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// All three ML-DSA variants can each act as a self-signed root CA.
    /// Consolidates per-variant coverage into a single test to reduce test runtime.
    #[tokio::test]
    async fn test_validate_pqc_all_mldsa_variants_as_self_signed_root() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        for (algo, label) in [
            (CryptographicAlgorithm::MLDSA_44, "ML-DSA-44"),
            (CryptographicAlgorithm::MLDSA_65, "ML-DSA-65"),
            (CryptographicAlgorithm::MLDSA_87, "ML-DSA-87"),
        ] {
            let (cert_id, _) =
                pqc_certify(&kms, &owner, algo, label, None, None, PQC_ROOT_EXT).await?;
            assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        }
        Ok(())
    }

    /// All three ML-KEM variants can each appear as a CA-issued leaf in a
    /// 2-level chain (RFC 9935).  A single ML-DSA-44 root signs all three leaves
    /// within the same KMS instance to verify AKI/SKI tracking is correct.
    #[tokio::test]
    async fn test_validate_pqc_all_mlkem_variants_as_ca_issued_leaf() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        // One shared root CA
        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;

        for (algo, label) in [
            (CryptographicAlgorithm::MLKEM_512, "ML-KEM-512 Leaf"),
            (CryptographicAlgorithm::MLKEM_768, "ML-KEM-768 Leaf"),
            (CryptographicAlgorithm::MLKEM_1024, "ML-KEM-1024 Leaf"),
        ] {
            let (leaf_id, _) = pqc_certify(
                &kms,
                &owner,
                algo,
                label,
                Some(&root_id),
                Some(&root_sk),
                PQC_LEAF_EXT,
            )
            .await?;
            assert_chain_valid(&kms, &owner, &[&root_id, &leaf_id]).await;
        }
        Ok(())
    }

    /// Duplicate cert IDs in the `unique_identifier` list are deduplicated by the
    /// validate operation — providing the root twice must still succeed.
    #[tokio::test]
    async fn test_validate_pqc_duplicate_ids_are_deduplicated() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        let (root_id, root_sk) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 Root CA",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;
        let (leaf_id, _) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_65,
            "ML-DSA-65 Leaf",
            Some(&root_id),
            Some(&root_sk),
            PQC_LEAF_EXT,
        )
        .await?;

        // Provide root twice — the server should deduplicate and still succeed.
        let req = Validate {
            certificate: None,
            unique_identifier: Some(vec![
                UniqueIdentifier::TextString(root_id.clone()),
                UniqueIdentifier::TextString(root_id.clone()),
                UniqueIdentifier::TextString(leaf_id.clone()),
                UniqueIdentifier::TextString(leaf_id.clone()),
            ]),
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await?;
        assert_eq!(res.validity_indicator, ValidityIndicator::Valid);
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // noRevAvail tests (RFC 9608)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Self-signed ML-DSA-44 certificate automatically gets id-ce-noRevAvail
    /// (OID 2.5.29.56, RFC 9608 §2) because it has no CRL DP.
    /// Chain validation must succeed (CRL check is skipped due to noRevAvail).
    #[tokio::test]
    async fn test_validate_pqc_self_signed_has_no_rev_avail() -> KResult<()> {
        // OID 2.5.29.56 — id-ce-noRevAvail (RFC 9608 §2), { id-ce 56 }
        // DER value bytes (without tag/length): 55 1D 38
        const NO_REV_AVAIL: &[u8] = &[0x55, 0x1d, 0x38];
        let kms = make_kms().await?;
        let owner = UserId::from("pqc_test_owner");

        // Certify a self-signed ML-DSA-44 cert with no crlDistributionPoints.
        let (cert_id, _sk_id) = pqc_certify(
            &kms,
            &owner,
            CryptographicAlgorithm::MLDSA_44,
            "ML-DSA-44 noRevAvail Root",
            None,
            None,
            PQC_ROOT_EXT,
        )
        .await?;

        // Retrieve the certificate DER bytes.
        let get_response = kms
            .get(
                Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(cert_id.clone())),
                    ..Get::default()
                },
                &owner,
            )
            .await?;
        let cert_der = match get_response.object {
            Object::Certificate(Certificate {
                certificate_value, ..
            }) => certificate_value,
            other => panic!("expected Certificate, got: {other:?}"),
        };

        // Parse the DER and assert that id-pe-noRevAvail (OID 1.3.6.1.5.5.7.1.56) is present.
        let (_, parsed) =
            X509Certificate::from_der(&cert_der).expect("failed to parse certificate DER");
        let has_no_rev_avail = parsed
            .extensions()
            .iter()
            .any(|ext| ext.oid.as_bytes() == NO_REV_AVAIL);
        assert!(
            has_no_rev_avail,
            "expected id-pe-noRevAvail extension (OID 1.3.6.1.5.5.7.1.56) in self-signed cert"
        );

        // Chain validation must succeed: noRevAvail triggers CRL skip in verify_crls.
        assert_chain_valid(&kms, &owner, &[&cert_id]).await;
        Ok(())
    }
}

// same tests but certs imported in kms.

/// Internal-state cascade tests for the KMIP `Validate` operation.
///
/// These cover two complementary revocation mechanisms:
/// - **External CRLs** (`crlDistributionPoints`, RFC 5280) — already supported by
///   `verify_crls`. Fixtures here use `file://` CRL URIs (test-build-only, see
///   `get_crl_bytes`) instead of the real `https://package.cosmian.com/...` URL the
///   original (now-replaced) `test_validate_with_certificates_bytes`/`_ids` tests
///   depended on, so these run unconditionally in CI with no network access.
/// - **Internal KMS lifecycle state** (`check_internal_certificate_states`) — a
///   certificate's own `Compromised` / `Deactivated` / `Destroyed` /
///   `Destroyed_Compromised` state, which a self-signed root CA's revocation can
///   *only* ever be observed through, since a root has no CDP of its own. Note
///   that for UID-supplied chains, a `Compromised` ancestor is *also* caught one
///   layer earlier by `retrieve_object_for_operation`'s per-state permission
///   matrix (which does not permit `Validate` on a `Compromised` object at all);
///   `check_internal_certificate_states` is what additionally covers a merely
///   `Deactivated` ancestor (which that permission gate explicitly allows through)
///   and chains supplied as raw bytes (which never go through that gate at all).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod internal_state_and_crl_cascade_tests {
    use std::sync::Arc;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
        kmip_2_1::{
            extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object},
            kmip_operations::{
                Certify, Get, GetAttributes, GetAttributesResponse, Revoke, Validate,
            },
            kmip_types::{
                CertificateAttributes, CryptographicAlgorithm, Link, LinkType,
                LinkedObjectIdentifier, UniqueIdentifier, ValidityIndicator, VendorAttribute,
                VendorAttributeValue,
            },
        },
    };

    use crate::{
        config::ServerParams, core::KMS, middlewares::UserId, result::KResult,
        tests::test_utils::https_clap_config,
    };

    /// Root CA extension — no CDP (self-signed roots have nothing "superior" to
    /// publish a CRL about them; this is exactly why the internal-state check is
    /// needed to ever detect a root's own revocation).
    const ROOT_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign
";

    /// Intermediate CA extension. `{cdp}` is substituted with a `file://` URI at
    /// runtime pointing to the root's CRL fixture.
    fn intermediate_ext(cdp_uri: &str) -> Vec<u8> {
        format!(
            "[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign
crlDistributionPoints=URI:{cdp_uri}
"
        )
        .into_bytes()
    }

    /// Leaf extension with a CDP pointing to the issuing CA's CRL fixture.
    fn leaf_ext(cdp_uri: &str) -> Vec<u8> {
        format!(
            "[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:FALSE
crlDistributionPoints=URI:{cdp_uri}
"
        )
        .into_bytes()
    }

    /// Leaf extension with no CDP at all (used for the pure internal-state tests,
    /// where we specifically want `verify_crls` to have nothing to check).
    const LEAF_EXT_NO_CDP: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:FALSE
";

    async fn make_kms() -> KResult<Arc<KMS>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        Ok(Arc::new(
            KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
        ))
    }

    /// Issue an RSA-2048 (FIPS-approved) certificate via KMIP `Certify`.
    async fn certify(
        kms: &Arc<KMS>,
        owner: &UserId,
        cn: &str,
        issuer_cert_id: Option<&str>,
        issuer_sk_id: Option<&str>,
        extension: &[u8],
    ) -> KResult<(String, String)> {
        let subject_name = format!("C=FR, O=KMS Test, CN={cn}");
        let mut links = Vec::new();
        if let Some(id) = issuer_cert_id {
            links.push(Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
            });
        }
        if let Some(id) = issuer_sk_id {
            links.push(Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(id.to_owned()),
            });
        }
        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(2048),
            certificate_attributes: Some(CertificateAttributes::parse_subject_line(&subject_name)?),
            link: if links.is_empty() { None } else { Some(links) },
            vendor_attributes: Some(vec![VendorAttribute {
                vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
                attribute_value: VendorAttributeValue::ByteString(extension.to_vec()),
            }]),
            ..Attributes::default()
        };
        let cert_id = kms
            .certify(
                Certify {
                    attributes: Some(attrs),
                    ..Certify::default()
                },
                owner,
            )
            .await?
            .unique_identifier
            .to_string();
        let GetAttributesResponse { attributes, .. } = kms
            .get_attributes(GetAttributes::from(cert_id.clone()), owner)
            .await?;
        let sk_id = attributes
            .get_link(LinkType::PrivateKeyLink)
            .expect("cert must have PrivateKeyLink")
            .to_string();
        Ok((cert_id, sk_id))
    }

    async fn revoke_cert(
        kms: &Arc<KMS>,
        owner: &UserId,
        cert_id: &str,
        reason: RevocationReasonCode,
    ) -> KResult<()> {
        kms.revoke(
            Revoke {
                unique_identifier: Some(UniqueIdentifier::TextString(cert_id.to_owned())),
                revocation_reason: RevocationReason {
                    revocation_reason_code: reason,
                    revocation_message: Some("internal_state_cascade_tests harness".to_owned()),
                },
                compromise_occurrence_date: None,
                cascade: false,
            },
            owner,
        )
        .await?;
        Ok(())
    }

    /// Generate a CRL for `ca_id` and write its DER bytes to `path` (overwriting).
    async fn write_crl_fixture(
        kms: &Arc<KMS>,
        owner: &UserId,
        ca_id: &str,
        path: &std::path::Path,
    ) {
        let crl = crate::core::operations::generate_crl::generate_crl(kms, ca_id, None, owner)
            .await
            .expect("generate_crl")
            .to_der()
            .expect("CRL to DER");
        std::fs::write(path, crl).expect("write CRL fixture");
    }

    /// Build a `file://` URI for an absolute path (three slashes: scheme + empty
    /// authority + absolute path), matching `SR-CRL-10`'s convention.
    ///
    /// This URI is embedded verbatim into an X.509 `crlDistributionPoints`
    /// extension via an OpenSSL `v3_ca`-style config string
    /// (`crlDistributionPoints=URI:{cdp_uri}`, see `leaf_ext`/`intermediate_ext`
    /// below). OpenSSL's NCONF value parser treats backslash (`\`) as an escape
    /// character, silently swallowing it and keeping only the following
    /// character — so a raw Windows path (`C:\Users\...`) fed through
    /// `path.display()` loses every path separator by the time the extension is
    /// parsed back out (`C:\Users\...` becomes `C:Users...`), which then fails
    /// downstream URI parsing with an obscure "invalid international domain
    /// name" error instead of a clear one. Always emit forward slashes — valid
    /// in a `file://` URI on every platform, and never treated as an escape
    /// character by OpenSSL's config parser — matching the same convention
    /// already used by `path_to_file_uri` in
    /// `crate/test_kms_server/src/vector_runner.rs` and
    /// `crate/clients/ckms/src/tests/certificates/certify.rs`.
    fn file_uri(path: &std::path::Path) -> String {
        #[cfg(windows)]
        {
            format!("file:///{}", path.to_string_lossy().replace('\\', "/"))
        }
        #[cfg(not(windows))]
        {
            format!("file://{}", path.display())
        }
    }

    async fn get_cert_der(kms: &Arc<KMS>, owner: &UserId, cert_id: &str) -> Vec<u8> {
        let resp = kms
            .get(
                Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(cert_id.to_owned())),
                    ..Get::default()
                },
                owner,
            )
            .await
            .expect("get cert");
        match resp.object {
            Object::Certificate(Certificate {
                certificate_value, ..
            }) => certificate_value,
            other => panic!("expected Certificate, got: {other:?}"),
        }
    }

    async fn validate_by_uid(kms: &Arc<KMS>, owner: &UserId, cert_ids: &[&str]) -> KResult<()> {
        let unique_identifiers = Some(
            cert_ids
                .iter()
                .map(|id| UniqueIdentifier::TextString((*id).to_owned()))
                .collect(),
        );
        let req = Validate {
            certificate: None,
            unique_identifier: unique_identifiers,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, owner)).await?;
        assert_eq!(res.validity_indicator, ValidityIndicator::Valid);
        Ok(())
    }

    async fn assert_validate_by_uid_invalid(kms: &Arc<KMS>, owner: &UserId, cert_ids: &[&str]) {
        let unique_identifiers = Some(
            cert_ids
                .iter()
                .map(|id| UniqueIdentifier::TextString((*id).to_owned()))
                .collect(),
        );
        let req = Validate {
            certificate: None,
            unique_identifier: unique_identifiers,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, owner)).await;
        assert!(res.is_err(), "expected chain to be Invalid, got: {res:?}");
    }

    /// Self-contained replacement for the old network-dependent
    /// `test_validate_with_certificates_bytes`/`_ids`: a leaf certificate revoked
    /// via `Revoke`, whose issuer's CRL (served from a local `file://` fixture, no
    /// network access) reflects the revocation once regenerated.
    #[tokio::test]
    async fn test_leaf_revocation_detected_via_file_crl() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("owner@example.com");
        let tmp = tempfile::tempdir().expect("tempdir");
        let crl_path = tmp.path().join("ca.crl.der");
        let crl_uri = file_uri(&crl_path);

        let (ca_id, _ca_sk) = certify(&kms, &owner, "Root CA", None, None, ROOT_EXT).await?;
        let (leaf_id, _leaf_sk) = certify(
            &kms,
            &owner,
            "leaf",
            Some(&ca_id),
            None,
            &leaf_ext(&crl_uri),
        )
        .await?;

        // Empty CRL published up front so the leaf's CDP fetch has something to read.
        write_crl_fixture(&kms, &owner, &ca_id, &crl_path).await;
        validate_by_uid(&kms, &owner, &[&ca_id, &leaf_id]).await?;

        revoke_cert(&kms, &owner, &leaf_id, RevocationReasonCode::KeyCompromise).await?;
        write_crl_fixture(&kms, &owner, &ca_id, &crl_path).await;
        assert_validate_by_uid_invalid(&kms, &owner, &[&ca_id, &leaf_id]).await;

        // Sanity: the raw-bytes path (no UID) reaches the same CRL-based conclusion.
        let ca_der = get_cert_der(&kms, &owner, &ca_id).await;
        let leaf_der = get_cert_der(&kms, &owner, &leaf_id).await;
        let req = Validate {
            certificate: Some(vec![ca_der, leaf_der]),
            unique_identifier: None,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "raw-bytes chain must also detect the CRL-based revocation, got: {res:?}"
        );
        Ok(())
    }

    /// 3-level chain: revoking the INTERMEDIATE CA (not the leaf) must invalidate
    /// the whole chain once the root's CRL is regenerated — this already worked
    /// before the internal-state fix (the intermediate has a CDP pointing at the
    /// root's CRL), and this test guards that existing CRL-cascade behaviour.
    #[tokio::test]
    async fn test_intermediate_compromise_cascade_via_crl() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("owner@example.com");
        let tmp = tempfile::tempdir().expect("tempdir");
        let root_crl_path = tmp.path().join("root.crl.der");
        let root_crl_uri = file_uri(&root_crl_path);

        let (root_id, _root_sk) = certify(&kms, &owner, "Root CA", None, None, ROOT_EXT).await?;
        let (intermediate_id, intermediate_sk) = certify(
            &kms,
            &owner,
            "Intermediate CA",
            Some(&root_id),
            None,
            &intermediate_ext(&root_crl_uri),
        )
        .await?;
        let (leaf_id, _leaf_sk) = certify(
            &kms,
            &owner,
            "leaf",
            Some(&intermediate_id),
            Some(&intermediate_sk),
            LEAF_EXT_NO_CDP,
        )
        .await?;

        write_crl_fixture(&kms, &owner, &root_id, &root_crl_path).await;
        validate_by_uid(&kms, &owner, &[&root_id, &intermediate_id, &leaf_id]).await?;

        revoke_cert(
            &kms,
            &owner,
            &intermediate_id,
            RevocationReasonCode::CACompromise,
        )
        .await?;
        write_crl_fixture(&kms, &owner, &root_id, &root_crl_path).await;

        assert_validate_by_uid_invalid(&kms, &owner, &[&root_id, &intermediate_id, &leaf_id]).await;
        Ok(())
    }

    /// A compromised ROOT CA makes a UID-supplied chain Invalid — a self-signed
    /// root has no CDP of its own, so its own compromise is invisible to
    /// `verify_crls`. **Note**: for this specific UID-supplied + `Compromised`
    /// combination, the failure is actually surfaced one layer earlier than the
    /// new `check_internal_certificate_states` — `retrieve_object_for_operation`'s
    /// per-state permission matrix does not allow `Validate` on a `Compromised`
    /// object at all, so `certificate_by_uid` itself fails with `Object_Not_Found`
    /// before the chain is even assembled. The customer-observable outcome (this
    /// test's actual assertion) is unaffected either way — the whole point of the
    /// new internal-state check is to also cover the cases that pre-existing gate
    /// does *not*: a merely `Deactivated` ancestor (see
    /// `test_deactivated_ancestor_also_invalidates_chain`, which the retrieval gate
    /// explicitly allows through) and chains supplied as raw bytes rather than by
    /// UID (see `test_raw_bytes_chain_detects_root_compromise`, which never goes
    /// through `retrieve_object_for_operation` at all).
    #[tokio::test]
    async fn test_root_compromise_now_detected_via_internal_state() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("owner@example.com");

        let (root_id, _root_sk) = certify(&kms, &owner, "Root CA", None, None, ROOT_EXT).await?;
        let (leaf_id, _leaf_sk) =
            certify(&kms, &owner, "leaf", Some(&root_id), None, LEAF_EXT_NO_CDP).await?;

        // Before compromise: perfectly valid (no CDP anywhere, nothing for
        // verify_crls to even check — this chain's validity rests entirely on
        // the internal-state check plus signature/date checks).
        validate_by_uid(&kms, &owner, &[&root_id, &leaf_id]).await?;

        revoke_cert(&kms, &owner, &root_id, RevocationReasonCode::CACompromise).await?;

        // The root itself is now Compromised in the KMS's own database — no CRL,
        // no OCSP query involved. `Validate` must catch this on its own.
        assert_validate_by_uid_invalid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// A merely `Deactivated` ancestor (voluntary retirement, not a compromise)
    /// also makes the whole chain Invalid: `Validate` returns one result for the
    /// entire supplied chain, and every certificate in it is expected to
    /// currently be Active/PreActive from the KMS's own point of view.
    #[tokio::test]
    async fn test_deactivated_ancestor_also_invalidates_chain() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("owner@example.com");

        let (root_id, _root_sk) = certify(&kms, &owner, "Root CA", None, None, ROOT_EXT).await?;
        let (leaf_id, _leaf_sk) =
            certify(&kms, &owner, "leaf", Some(&root_id), None, LEAF_EXT_NO_CDP).await?;

        validate_by_uid(&kms, &owner, &[&root_id, &leaf_id]).await?;

        // `Unspecified` maps to Deactivated (not Compromised) — see revoke.rs.
        revoke_cert(&kms, &owner, &root_id, RevocationReasonCode::Unspecified).await?;

        assert_validate_by_uid_invalid(&kms, &owner, &[&root_id, &leaf_id]).await;
        Ok(())
    }

    /// The internal-state check also applies to chains supplied as raw DER bytes
    /// (no `UniqueIdentifier`), via an exact-byte match against KMS records
    /// (`find_certificate_state_by_der`) — not just UID-supplied chains.
    #[tokio::test]
    async fn test_raw_bytes_chain_detects_root_compromise() -> KResult<()> {
        let kms = make_kms().await?;
        let owner = UserId::from("owner@example.com");

        let (root_id, _root_sk) = certify(&kms, &owner, "Root CA", None, None, ROOT_EXT).await?;
        let (leaf_id, _leaf_sk) =
            certify(&kms, &owner, "leaf", Some(&root_id), None, LEAF_EXT_NO_CDP).await?;
        let root_der = get_cert_der(&kms, &owner, &root_id).await;
        let leaf_der = get_cert_der(&kms, &owner, &leaf_id).await;

        // Valid before compromise, supplied purely as raw bytes.
        let req = Validate {
            certificate: Some(vec![root_der.clone(), leaf_der.clone()]),
            unique_identifier: None,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await?;
        assert_eq!(res.validity_indicator, ValidityIndicator::Valid);

        revoke_cert(&kms, &owner, &root_id, RevocationReasonCode::CACompromise).await?;

        let req = Validate {
            certificate: Some(vec![root_der, leaf_der]),
            unique_identifier: None,
            validity_time: None,
        };
        let res = Box::pin(kms.validate(req, &owner)).await;
        assert!(
            res.is_err(),
            "raw-bytes chain must detect the root's internal compromise via exact-DER match, \
             got: {res:?}"
        );
        Ok(())
    }
}
