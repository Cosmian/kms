#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::{fs, io::Write, path::Path, process::Command};

use cosmian_kms_client::{
    cosmian_kmip::time_normalize,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::{Create, Decrypt, Destroy, Encrypt, Export, SignatureVerify},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier, ValidityIndicator},
    },
};
use tempfile::TempDir;

use crate::{init_test_logging, start_default_test_kms_server};

fn gpg_bin() -> Option<String> {
    if let Ok(output) = Command::new("which").arg("gpg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    None
}

/// Runs gpg inside an isolated, 0700 temp GNUPGHOME with
/// `--batch --yes --no-tty --pinentry-mode loopback --passphrase ""`.
fn run_gpg(
    home: &Path,
    args: &[&str],
    stdin_data: Option<&[u8]>,
) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new("gpg");
    cmd.env("GNUPGHOME", home.to_str().unwrap());
    cmd.args([
        "--batch",
        "--yes",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
    ]);
    cmd.args(args);

    if stdin_data.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn gpg");
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).expect("failed to write to gpg stdin");
        }
    }

    let output = child.wait_with_output().expect("failed to wait on gpg");
    (output.status, output.stdout, output.stderr)
}

fn create_gpg_home() -> TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir.path(), perms).unwrap();
    }
    dir
}

fn pgp_create_request(alg: CryptographicAlgorithm, bits: Option<i32>) -> Create {
    Create {
        object_type: cosmian_kms_client::kmip_2_1::kmip_objects::ObjectType::PGPKey,
        attributes: Attributes {
            object_type: Some(cosmian_kms_client::kmip_2_1::kmip_objects::ObjectType::PGPKey),
            cryptographic_algorithm: Some(alg),
            cryptographic_length: bits,
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign
                    | CryptographicUsageMask::Verify
                    | CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt,
            ),
            activation_date: Some(time_normalize().unwrap()),
            ..Attributes::default()
        },
        protection_storage_masks: None,
    }
}

#[tokio::test]
async fn test_pgp_gnupg_kms_encrypt_gpg_decrypt() {
    if gpg_bin().is_none() {
        println!("Skipping test_pgp_gnupg_kms_encrypt_gpg_decrypt: gpg not found");
        return;
    }
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(3072));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let export_resp = client.export(Export::from(uid.clone())).await.unwrap();
    let secret_bytes = export_resp.object.key_block().unwrap().key_bytes().unwrap();

    let gpg_home = create_gpg_home();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&secret_bytes));
    assert!(
        status.success(),
        "gpg --import failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let plaintext = b"Hello from KMS to GnuPG via OpenPGP encryption!";
    let enc_req = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
        ..Encrypt::default()
    };
    let enc_resp = client.encrypt(enc_req).await.unwrap();
    let ciphertext = enc_resp.data.expect("ciphertext");

    let cipher_file = gpg_home.path().join("msg.gpg");
    fs::write(&cipher_file, &ciphertext).unwrap();

    let (status, stdout, stderr) = run_gpg(
        gpg_home.path(),
        &["--decrypt", cipher_file.to_str().unwrap()],
        None,
    );
    assert!(
        status.success(),
        "gpg --decrypt failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(&stdout[..], plaintext);

    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}

#[tokio::test]
async fn test_pgp_gnupg_gpg_encrypt_kms_decrypt() {
    if gpg_bin().is_none() {
        println!("Skipping test_pgp_gnupg_gpg_encrypt_kms_decrypt: gpg not found");
        return;
    }
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(3072));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let export_pub_req = Export::new(
        UniqueIdentifier::TextString(uid.clone()),
        false,
        None,
        Some(KeyFormatType::OpenPgpPublicKey),
    );
    let export_pub_resp = client.export(export_pub_req).await.unwrap();
    let pub_bytes = export_pub_resp
        .object
        .key_block()
        .unwrap()
        .key_bytes()
        .unwrap();

    let gpg_home = create_gpg_home();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&pub_bytes));
    assert!(
        status.success(),
        "gpg --import public key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let (status, stdout, _) = run_gpg(gpg_home.path(), &["--list-keys", "--with-colons"], None);
    assert!(status.success());
    let list_output = String::from_utf8_lossy(&stdout);
    let mut key_fingerprint: Option<String> = None;
    for line in list_output.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts
            .first()
            .is_some_and(|s| s.starts_with("fp") && s.ends_with('r') && s.len() == 3)
            && parts.len() > 9
        {
            if let Some(f) = parts.get(9) {
                key_fingerprint = Some((*f).to_owned());
                break;
            }
        }
    }
    let recipient_fingerprint = key_fingerprint.expect("fingerprint from gpg --list-keys");

    let plaintext = b"Hello from GnuPG to KMS Decrypt!";
    let plain_file = gpg_home.path().join("plain.txt");
    fs::write(&plain_file, plaintext).unwrap();

    let cipher_file = gpg_home.path().join("cipher.gpg");
    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--trust-model",
            "always",
            "--recipient",
            &recipient_fingerprint,
            "--output",
            cipher_file.to_str().unwrap(),
            "--encrypt",
            plain_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --encrypt failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let ciphertext = fs::read(&cipher_file).unwrap();
    let dec_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(ciphertext),
        ..Decrypt::default()
    };
    let dec_resp = client.decrypt(dec_req).await.unwrap();
    let decrypted = dec_resp.data.expect("decrypted data");
    assert_eq!(&decrypted[..], plaintext);

    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}

#[tokio::test]
async fn test_pgp_gnupg_kms_sign_gpg_verify() {
    if gpg_bin().is_none() {
        println!("Skipping test_pgp_gnupg_kms_sign_gpg_verify: gpg not found");
        return;
    }
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(3072));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let export_pub_req = Export::new(
        UniqueIdentifier::TextString(uid.clone()),
        false,
        None,
        Some(KeyFormatType::OpenPgpPublicKey),
    );
    let export_pub_resp = client.export(export_pub_req).await.unwrap();
    let pub_bytes = export_pub_resp
        .object
        .key_block()
        .unwrap()
        .key_bytes()
        .unwrap();

    let gpg_home = create_gpg_home();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&pub_bytes));
    assert!(
        status.success(),
        "gpg --import public key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let data = b"payload to be signed by KMS and verified by GnuPG";
    let sign_req = cosmian_kms_client::kmip_2_1::kmip_operations::Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(zeroize::Zeroizing::new(data.to_vec())),
        ..cosmian_kms_client::kmip_2_1::kmip_operations::Sign::default()
    };
    let sign_resp = client.sign(sign_req).await.unwrap();
    let signature = sign_resp.signature_data.expect("signature data");

    let sig_file = gpg_home.path().join("data.sig");
    let data_file = gpg_home.path().join("data.txt");
    fs::write(&sig_file, &signature).unwrap();
    fs::write(&data_file, data).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--verify",
            sig_file.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --verify failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}

#[tokio::test]
async fn test_pgp_gnupg_gpg_sign_kms_verify() {
    if gpg_bin().is_none() {
        println!("Skipping test_pgp_gnupg_gpg_sign_kms_verify: gpg not found");
        return;
    }
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(3072));
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let export_resp = client.export(Export::from(uid.clone())).await.unwrap();
    let secret_bytes = export_resp.object.key_block().unwrap().key_bytes().unwrap();

    let gpg_home = create_gpg_home();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&secret_bytes));
    assert!(
        status.success(),
        "gpg --import secret key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let data = b"payload signed by GnuPG and verified by KMS";
    let data_file = gpg_home.path().join("data_gpg.txt");
    let sig_file = gpg_home.path().join("data_gpg.sig");
    fs::write(&data_file, data).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--detach-sign",
            "--output",
            sig_file.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --detach-sign failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let signature = fs::read(&sig_file).unwrap();

    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        data: Some(data.to_vec()),
        signature_data: Some(signature),
        ..SignatureVerify::default()
    };
    let verify_resp = client.signature_verify(verify_req).await.unwrap();
    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}
