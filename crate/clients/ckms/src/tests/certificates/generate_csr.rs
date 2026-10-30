use cosmian_logger::log_init;
use openssl::x509::{X509, X509Req};
use tempfile::TempDir;
use test_kms_server::{
    TestClientOptions, hsm_config_path, start_default_test_kms_server, start_test_server_with_patch,
};
use uuid::Uuid;

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::CertificateExportFormat;

use super::{
    certify::{CertifyOp, certify, import_root_and_intermediate},
    export::export_certificate,
};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
        utils::{ckms_bin, owner_config, recover_cmd_logs},
    },
};

fn generate_csr(
    cli_conf_path: &str,
    private_key_id: &str,
    subject_name: &str,
    output_file: &std::path::Path,
) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args([
        "certificates",
        "generate-csr",
        "--private-key-id",
        private_key_id,
    ])
    .args(["--subject-name", subject_name])
    .arg("--output-file")
    .arg(output_file);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// `ckms certificates generate-csr <args>`: returns stdout, or stderr as an error.
fn generate_csr_args(cli_conf_path: &str, args: &[&str]) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args(["certificates", "generate-csr"]).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(std::str::from_utf8(&output.stdout)?.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// The value printed after `label` on its line of the command output.
fn printed_value<'a>(stdout: &'a str, label: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.split_once(label).map(|(_, value)| value))
        .unwrap_or_else(|| panic!("no '{label}' in: {stdout}"))
        .trim()
}

/// A sub-CA CSR is generated for a key kept in the KMS, signed by a CA, and the resulting
/// certificate carries the key of the CSR.
#[tokio::test]
async fn test_generate_csr_for_kms_held_key_and_certify_it() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();

    let (private_key_id, _public_key_id) = create_rsa_key_pair(
        &conf,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;
    let csr_file = tmp_dir.path().join("subca.csr");
    generate_csr(
        &conf,
        &private_key_id,
        "C=FR, O=Acme, CN=Acme Sub CA",
        &csr_file,
    )?;

    let csr = X509Req::from_pem(&std::fs::read(&csr_file).unwrap()).unwrap();
    assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
    let cn = csr
        .subject_name()
        .entries()
        .last()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned());
    assert_eq!(cn.as_deref(), Some("Acme Sub CA"));

    // The "offline root" signs it.
    let (_root_id, _intermediate_id, issuer_private_key_id) = import_root_and_intermediate(&conf)?;
    let certificate_id = certify(
        &conf,
        CertifyOp {
            csr_file: Some(csr_file.to_string_lossy().into_owned()),
            issuer_private_key_id: Some(issuer_private_key_id),
            ..Default::default()
        },
    )?;
    let pem_file = tmp_dir.path().join("subca.pem");
    export_certificate(
        &conf,
        &certificate_id,
        pem_file.to_str().unwrap(),
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;
    let certificate = X509::from_pem(&std::fs::read(&pem_file).unwrap()).unwrap();
    assert!(
        certificate
            .public_key()
            .unwrap()
            .public_eq(csr.public_key().unwrap().as_ref())
    );
    Ok(())
}

/// Create an RSA key pair in `SoftHSM2` and issue a CA certificate for it: self-signed when
/// `issuer` is `None`, otherwise from a CSR generated for the HSM private key and signed by
/// `issuer = (issuer certificate id, issuer private key id)`. Returns `(HSM private key id,
/// certificate id, certificate)`.
fn hsm_ca_certificate(
    conf: &str,
    slot: usize,
    tmp_dir: &TempDir,
    subject: &str,
    issuer: Option<(&str, &str)>,
) -> CosmianResult<(String, String, X509)> {
    let (private_key_id, public_key_id) = create_rsa_key_pair(
        conf,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            sensitive: true,
            key_id: Some(format!("hsm::{slot}::{}", Uuid::new_v4())),
            ..Default::default()
        },
    )?;
    assert!(private_key_id.starts_with(&format!("hsm::{slot}::")));
    assert!(public_key_id.starts_with(&format!("hsm::{slot}::")));

    let extensions = tmp_dir.path().join("ca.ext");
    std::fs::write(
        &extensions,
        "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,crlSign\n",
    )?;
    let mut op = CertifyOp {
        subject_name: Some(subject.to_owned()),
        certificate_extensions: Some(extensions),
        ..Default::default()
    };
    let mut csr_public_key = None;
    if let Some((issuer_certificate_id, issuer_private_key_id)) = issuer {
        let csr_file = tmp_dir.path().join(format!("{}.csr", Uuid::new_v4()));
        generate_csr(conf, &private_key_id, subject, &csr_file)?;
        let ossl = |e: openssl::error::ErrorStack| CosmianError::Default(e.to_string());
        let csr = X509Req::from_pem(&std::fs::read(&csr_file)?).map_err(ossl)?;
        assert!(
            csr.verify(csr.public_key().map_err(ossl)?.as_ref())
                .map_err(ossl)?
        );
        csr_public_key = Some(csr.public_key().map_err(ossl)?);
        op.csr_file = Some(csr_file.to_string_lossy().into_owned());
        op.issuer_certificate_id = Some(issuer_certificate_id.to_owned());
        op.issuer_private_key_id = Some(issuer_private_key_id.to_owned());
    } else {
        op.public_key_id_to_certify = Some(public_key_id);
    }
    let certificate_id = certify(conf, op)?;

    let pem_file = tmp_dir.path().join(format!("{}.pem", Uuid::new_v4()));
    export_certificate(
        conf,
        &certificate_id,
        pem_file
            .to_str()
            .ok_or_else(|| CosmianError::Default("non UTF-8 path".to_owned()))?,
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;
    let certificate = X509::from_pem(&std::fs::read(&pem_file)?)
        .map_err(|e| CosmianError::Default(e.to_string()))?;
    if let Some(csr_public_key) = csr_public_key {
        assert!(
            certificate
                .public_key()
                .map_err(|e| CosmianError::Default(e.to_string()))?
                .public_eq(&csr_public_key)
        );
    }
    Ok((private_key_id, certificate_id, certificate))
}

/// Same flow as above, but the root, intermediate and CSR private keys are all non-extractable
/// key pairs created and kept in `SoftHSM2`: the KMS database only holds the certificates. The
/// CSRs are signed by the HSM and the certificates by the HSM issuer keys.
#[tokio::test]
#[ignore = "Requires SoftHSM2 (HSM_SLOT_ID, optional HSM_USER_PASSWORD, SOFTHSM2_CONF)"]
async fn test_generate_csr_for_softhsm2_held_keys_and_certify_them() -> CosmianResult<()> {
    log_init(None);
    let slot: usize = std::env::var("HSM_SLOT_ID").unwrap().parse().unwrap();
    let password = std::env::var("HSM_USER_PASSWORD").unwrap_or_else(|_| "12345678".to_owned());
    // plain-HTTP server whose only HSM is the SoftHSM2 slot under test
    let ctx = start_test_server_with_patch(
        &hsm_config_path("three_softhsm2.toml"),
        move |config| {
            config.hsm.hsm_slot = vec![slot];
            config.hsm.hsm_password = vec![password];
            config.hsm_instances.clear();
        },
        TestClientOptions::default(),
    )
    .await
    .unwrap();
    let conf = owner_config(&ctx);
    let tmp_dir = TempDir::new().unwrap();

    // "offline root", self-signed from the HSM public key
    let (root_sk, root_id, root) = hsm_ca_certificate(
        &conf,
        slot,
        &tmp_dir,
        "C=FR, O=Acme, CN=Acme HSM Root",
        None,
    )?;
    assert!(root.verify(root.public_key().unwrap().as_ref()).unwrap());

    // intermediate: HSM CSR signed by the HSM root key
    let (intermediate_sk, intermediate_id, intermediate) = hsm_ca_certificate(
        &conf,
        slot,
        &tmp_dir,
        "C=FR, O=Acme, CN=Acme HSM Intermediate",
        Some((&root_id, &root_sk)),
    )?;
    assert!(
        intermediate
            .verify(root.public_key().unwrap().as_ref())
            .unwrap()
    );

    // sub-CA: HSM CSR signed by the HSM intermediate key
    let (_sub_sk, _sub_id, sub) = hsm_ca_certificate(
        &conf,
        slot,
        &tmp_dir,
        "C=FR, O=Acme, CN=Acme HSM Sub CA",
        Some((&intermediate_id, &intermediate_sk)),
    )?;
    assert!(
        sub.verify(intermediate.public_key().unwrap().as_ref())
            .unwrap()
    );

    // the CSR command can generate the non-extractable key pair in the HSM itself
    let hsm_key_id = format!("hsm::{slot}::{}", Uuid::new_v4());
    let csr_file = tmp_dir.path().join("generated-in-hsm.csr");
    let stdout = generate_csr_args(
        &conf,
        &[
            "--algorithm",
            "nist-p256",
            "--sensitive",
            "--private-key-id",
            &hsm_key_id,
            "--subject-name",
            "C=FR, O=Acme, CN=Acme HSM Generated",
            "--output-file",
            csr_file.to_str().unwrap(),
        ],
    )?;
    assert_eq!(printed_value(&stdout, "Private key id:"), hsm_key_id);
    let csr = X509Req::from_pem(&std::fs::read(&csr_file).unwrap()).unwrap();
    assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
    Ok(())
}

#[tokio::test]
async fn test_generate_csr_rejects_a_public_key_and_a_bad_subject() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();
    let (private_key_id, public_key_id) =
        create_rsa_key_pair(&conf, &RsaKeyPairOptions::default())?;
    let out = tmp_dir.path().join("x.csr");
    assert!(generate_csr(&conf, &public_key_id, "CN=x", &out).is_err());
    assert!(generate_csr(&conf, &private_key_id, "not a dn", &out).is_err());
    assert!(!out.exists(), "no CSR file is written on failure");
    Ok(())
}

/// `--algorithm` generates the key pair, signs the CSR with it, and prints the key ids; the
/// private key is then usable by `--private-key-id`.
#[tokio::test]
async fn test_generate_csr_generating_the_key_pair() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();

    for algorithm in ["nist-p256", "rsa2048"] {
        let csr_file = tmp_dir.path().join(format!("{algorithm}.csr"));
        let csr_path = csr_file.to_str().unwrap();
        let stdout = generate_csr_args(
            &conf,
            &[
                "--algorithm",
                algorithm,
                "--subject-name",
                "C=FR, O=Acme, CN=Generated",
                "--output-file",
                csr_path,
            ],
        )?;
        let private_key_id = printed_value(&stdout, "Private key id:").to_owned();
        assert!(!printed_value(&stdout, "Public key id:").is_empty());
        let csr = X509Req::from_pem(&std::fs::read(&csr_file).unwrap()).unwrap();
        assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
        assert_eq!(
            csr.public_key().unwrap().id(),
            if algorithm == "rsa2048" {
                openssl::pkey::Id::RSA
            } else {
                openssl::pkey::Id::EC
            }
        );

        // the generated private key signs a second CSR on its own
        generate_csr(&conf, &private_key_id, "CN=Again", &csr_file)?;
    }

    // a chosen id is honoured
    let id = Uuid::new_v4().to_string();
    let csr_file = tmp_dir.path().join("chosen.csr");
    let stdout = generate_csr_args(
        &conf,
        &[
            "--algorithm",
            "nist-p384",
            "--private-key-id",
            &id,
            "--subject-name",
            "CN=Chosen",
            "--output-file",
            csr_file.to_str().unwrap(),
        ],
    )?;
    assert_eq!(printed_value(&stdout, "Private key id:"), id);
    Ok(())
}

#[tokio::test]
async fn test_generate_csr_key_pair_generation_errors() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();
    let out = tmp_dir.path().join("x.csr");
    let out = out.to_str().unwrap();
    let base = ["--subject-name", "CN=x", "--output-file", out];

    // neither a key nor an algorithm
    generate_csr_args(&conf, &base).unwrap_err();
    // `--sensitive` only applies to a generated key pair
    generate_csr_args(
        &conf,
        &[&base[..], &["--private-key-id", "x", "--sensitive"]].concat(),
    )
    .unwrap_err();
    // unknown algorithm
    generate_csr_args(&conf, &[&base[..], &["--algorithm", "nope"]].concat()).unwrap_err();
    // an HSM key pair must be sensitive: refused before anything is created
    let err = generate_csr_args(
        &conf,
        &[
            &base[..],
            &["--algorithm", "nist-p256", "--private-key-id", "hsm::0::x"],
        ]
        .concat(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("must be sensitive"), "{err}");
    // a key encapsulation key cannot sign
    #[cfg(feature = "non-fips")]
    {
        let err = generate_csr_args(&conf, &[&base[..], &["--algorithm", "ml-kem-512"]].concat())
            .unwrap_err();
        assert!(err.to_string().contains("cannot sign"), "{err}");
        // ML-DSA keys cannot be created in an HSM: refused up front
        let err = generate_csr_args(
            &conf,
            &[
                &base[..],
                &[
                    "--algorithm",
                    "ml-dsa-44",
                    "--sensitive",
                    "--private-key-id",
                    "hsm::0::x",
                ],
            ]
            .concat(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("HSM cannot generate"), "{err}");
    }
    assert!(
        !std::path::Path::new(out).exists(),
        "no CSR file is written on failure"
    );

    // a malformed subject is refused before the key pair is created: the id is still free
    let id = Uuid::new_v4().to_string();
    let run = |subject: &str| {
        generate_csr_args(
            &conf,
            &[
                "--algorithm",
                "nist-p256",
                "--private-key-id",
                &id,
                "--subject-name",
                subject,
                "--output-file",
                out,
            ],
        )
    };
    for bad in ["CN=a\\", "not a dn", " "] {
        assert!(run(bad).is_err(), "{bad:?}");
    }
    run("CN=ok")?;
    Ok(())
}
