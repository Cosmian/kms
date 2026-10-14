#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::{
    fmt::Write as FmtWrite,
    fs,
    io::Write,
    path::Path,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cosmian_kms_client::{
    KmsClient, KmsClientError,
    cosmian_kmip::time_normalize,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::{VENDOR_ATTR_PGP_USER_ID, tagging::VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PGPKey},
        kmip_operations::{
            Create, Decrypt, Destroy, Encrypt, Export, Import, Sign, SignatureVerify,
        },
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, UniqueIdentifier, ValidityIndicator,
            VendorAttributeValue,
        },
    },
};
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::{init_test_logging, start_default_test_kms_server};
static NEXT_PGP_IMPORT_UID: AtomicU64 = AtomicU64::new(0);

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

/// Create an **unprotected** key inside gpg. `algo` is a `--quick-generate-key`
/// algorithm string: "ed25519", "rsa2048", "rsa3072", "rsa4096".
/// Returns (fingerprint, armored secret key, armored public key).
fn gpg_create_key(home: &Path, uid: &str, algo: &str) -> (String, Vec<u8>, Vec<u8>) {
    // Generate key with an encryption subkey using unattended batch parameter file
    let (key_type, key_curve, key_length, subkey_type, subkey_curve, subkey_length) = match algo {
        "ed25519" => (
            "eddsa",
            Some("ed25519"),
            None,
            "ecdh",
            Some("cv25519"),
            None,
        ),
        "rsa2048" => ("RSA", None, Some(2048), "RSA", None, Some(2048)),
        "rsa3072" => ("RSA", None, Some(3072), "RSA", None, Some(3072)),
        "rsa4096" => ("RSA", None, Some(4096), "RSA", None, Some(4096)),
        other => panic!("unsupported algo for gpg_create_key: {other}"),
    };

    let mut script = String::new();
    let _ = writeln!(script, "Key-Type: {key_type}");
    if let Some(c) = key_curve {
        let _ = writeln!(script, "Key-Curve: {c}");
    }
    if let Some(l) = key_length {
        let _ = writeln!(script, "Key-Length: {l}");
    }
    script.push_str("Key-Usage: sign,cert\n");
    let _ = writeln!(script, "Subkey-Type: {subkey_type}");
    if let Some(c) = subkey_curve {
        let _ = writeln!(script, "Subkey-Curve: {c}");
    }
    if let Some(l) = subkey_length {
        let _ = writeln!(script, "Subkey-Length: {l}");
    }
    script.push_str("Subkey-Usage: encrypt\n");
    script.push_str(
        "Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed\n",
    );
    let _ = writeln!(script, "Name-Real: {uid}");
    script.push_str("Expire-Date: 0\n");
    script.push_str("%no-protection\n");
    script.push_str("%commit\n");
    let (status, _, stderr) = run_gpg(home, &["--generate-key"], Some(script.as_bytes()));
    assert!(
        status.success(),
        "gpg generate-key failed for {algo}: {}",
        String::from_utf8_lossy(&stderr)
    );

    let (status, stdout, stderr) = run_gpg(home, &["--list-keys", "--with-colons"], None);
    assert!(
        status.success(),
        "list-keys failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    let list_output = String::from_utf8_lossy(&stdout);
    let mut fpr = None;
    for line in list_output.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.first() == Some(&"fpr") && parts.len() > 9 {
            // typos:ignore
            fpr = parts.get(9).map(|s| (*s).to_owned());
            break;
        }
    }
    let fingerprint = fpr.expect("fingerprint from gpg_create_key");

    let (status, secret_armor, stderr) =
        run_gpg(home, &["--armor", "--export-secret-keys", uid], None);
    assert!(
        status.success(),
        "export-secret-keys failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let (status, public_armor, stderr) = run_gpg(home, &["--armor", "--export", uid], None);
    assert!(
        status.success(),
        "export public failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    (fingerprint, secret_armor, public_armor)
}

/// Create a key protected by `passphrase` (used only by the negative test).
fn gpg_create_protected_key(home: &Path, uid: &str, algo: &str, passphrase: &str) -> Vec<u8> {
    let mut cmd = Command::new("gpg");
    cmd.env("GNUPGHOME", home.to_str().unwrap());
    cmd.args([
        "--batch",
        "--yes",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,
        "--quick-generate-key",
        uid,
        algo,
        "default",
        "never",
    ]);
    let out = cmd.output().expect("failed to run gpg quick-generate-key");
    assert!(
        out.status.success(),
        "protected key gen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut exp_cmd = Command::new("gpg");
    exp_cmd.env("GNUPGHOME", home.to_str().unwrap());
    exp_cmd.args([
        "--batch",
        "--yes",
        "--no-tty",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,
        "--armor",
        "--export-secret-keys",
        uid,
    ]);
    let exp_out = exp_cmd.output().expect("failed to export protected key");
    assert!(
        exp_out.status.success(),
        "export protected key failed: {}",
        String::from_utf8_lossy(&exp_out.stderr)
    );
    exp_out.stdout
}

/// Import armored key material into the shared KMS under a process-unique UID.
async fn kms_import_pgp(client: &KmsClient, armored: &[u8]) -> Result<String, KmsClientError> {
    let import_uid = format!(
        "imported-pgp-{}-{}",
        std::process::id(),
        NEXT_PGP_IMPORT_UID.fetch_add(1, Ordering::Relaxed),
    );
    let import_object = Object::PGPKey(PGPKey {
        pgp_key_version: 4,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::OpenPgpSecretKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(armored.to_vec())),
                attributes: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_req = Import {
        unique_identifier: UniqueIdentifier::TextString(import_uid.clone()),
        replace_existing: Some(false),
        object_type: ObjectType::PGPKey,
        object: import_object,
        attributes: Attributes {
            object_type: Some(ObjectType::PGPKey),
            activation_date: Some(time_normalize().unwrap()),
            ..Attributes::default()
        },
        key_wrap_type: None,
    };

    client.import(import_req).await?;
    Ok(import_uid)
}

/// Export a KMS PGP key as secret or public armor.
async fn kms_export_pgp(
    client: &KmsClient,
    uid: &str,
    public_only: bool,
) -> Result<Vec<u8>, KmsClientError> {
    let format = if public_only {
        KeyFormatType::OpenPgpPublicKey
    } else {
        KeyFormatType::OpenPgpSecretKey
    };
    let export_req = Export::new(
        UniqueIdentifier::TextString(uid.to_owned()),
        false,
        None,
        Some(format),
    );
    let resp = client.export(export_req).await?;
    let bytes = resp
        .object
        .key_block()
        .expect("key_block")
        .key_bytes()
        .expect("key_bytes");
    Ok(bytes.to_vec())
}

fn pgp_create_request(alg: CryptographicAlgorithm, bits: Option<i32>) -> Create {
    Create {
        object_type: ObjectType::PGPKey,
        attributes: Attributes {
            object_type: Some(ObjectType::PGPKey),
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

async fn destroy_key(client: &KmsClient, uid: &str) {
    drop(
        client
            .destroy(Destroy {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                remove: true,
                cascade: true,
                ..Destroy::default()
            })
            .await,
    );
}

// ============================================================================
// Direction 1 — Key born in gpg, used by the KMS
// ============================================================================

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_ed25519_imported_kms_decrypts() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "GPG Ed25519 <gpg-ed@example.com>";
    let (_fpr, secret_armor, _pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");

    let kms_uid = kms_import_pgp(&client, &secret_armor).await.unwrap();

    let plaintext = b"Hello from GnuPG Ed25519/cv25519 to KMS Decrypt!";
    let plain_file = gpg_home.path().join("plain.txt");
    fs::write(&plain_file, plaintext).unwrap();
    let cipher_file = gpg_home.path().join("msg.gpg");

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--trust-model",
            "always",
            "--recipient",
            uid_str,
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
    let dec_resp = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(ciphertext),
            ..Decrypt::default()
        })
        .await
        .unwrap();

    assert_eq!(
        dec_resp.data.as_deref().map(|v| &v[..]),
        Some(&plaintext[..])
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_rsa3072_imported_kms_decrypts() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "GPG RSA3072 <gpg-rsa@example.com>";
    let (_fpr, secret_armor, _pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "rsa3072");

    let kms_uid = kms_import_pgp(&client, &secret_armor).await.unwrap();

    let plaintext = b"Hello from GnuPG RSA-3072 to KMS Decrypt!";
    let plain_file = gpg_home.path().join("plain_rsa.txt");
    fs::write(&plain_file, plaintext).unwrap();
    let cipher_file = gpg_home.path().join("msg_rsa.gpg");

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--trust-model",
            "always",
            "--recipient",
            uid_str,
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
    let dec_resp = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(ciphertext),
            ..Decrypt::default()
        })
        .await
        .unwrap();

    assert_eq!(
        dec_resp.data.as_deref().map(|v| &v[..]),
        Some(&plaintext[..])
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_imported_kms_signs_gpg_verifies() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "GPG Signer <signer@example.com>";
    let (_fpr, secret_armor, _pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");

    let kms_uid = kms_import_pgp(&client, &secret_armor).await.unwrap();

    let data = b"data to sign with imported gpg key in KMS";
    let sign_resp = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(zeroize::Zeroizing::new(data.to_vec())),
            ..Sign::default()
        })
        .await
        .unwrap();
    let sig_bytes = sign_resp.signature_data.expect("signature_data");

    let sig_file = gpg_home.path().join("kms_made.sig");
    let data_file = gpg_home.path().join("data_for_kms_sig.txt");
    fs::write(&sig_file, &sig_bytes).unwrap();
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
        "gpg --verify of KMS signature failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_public_only_import_then_kms_encrypts() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "GPG PubOnly <pubonly@example.com>";
    let (_fpr, _secret_armor, pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");

    let kms_uid = kms_import_pgp(&client, &pub_armor).await.unwrap();

    let plaintext = b"Confidential message for GnuPG private keyholder";
    let enc_resp = client
        .encrypt(Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
            ..Encrypt::default()
        })
        .await
        .unwrap();
    let ciphertext = enc_resp.data.expect("ciphertext");

    let cipher_file = gpg_home.path().join("kms_enc.gpg");
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

    // Assert KMS Sign fails on public-only key
    let sign_res = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(zeroize::Zeroizing::new(b"hello".to_vec())),
            ..Sign::default()
        })
        .await;
    assert!(
        sign_res.is_err(),
        "signing with public-only key should fail"
    );

    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_protected_key_import_cannot_sign() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let protected_armor = gpg_create_protected_key(
        gpg_home.path(),
        "Protected <p@example.com>",
        "ed25519",
        "correct horse",
    );
    let kms_uid = kms_import_pgp(&client, &protected_armor).await.unwrap();

    let sign_res = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(zeroize::Zeroizing::new(b"cannot sign".to_vec())),
            ..Sign::default()
        })
        .await;

    assert!(
        sign_res.is_err(),
        "signing with passphrase-protected key must fail"
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_subkey_signature_verifies() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let lines = [
        "Key-Type: eddsa",
        "Key-Curve: ed25519",
        "Key-Usage: cert",
        "Subkey-Type: eddsa",
        "Subkey-Curve: ed25519",
        "Subkey-Usage: sign",
        "Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP Uncompressed",
        "Name-Real: Subkey User <sub@example.com>",
        "Expire-Date: 0",
        "%no-protection",
        "%commit",
        "",
    ];
    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &["--generate-key"],
        Some(lines.join("\n").as_bytes()),
    );
    assert!(
        status.success(),
        "generate-key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    // Get subkey fingerprint
    let (status, stdout, _) = run_gpg(gpg_home.path(), &["--list-keys", "--with-colons"], None);
    assert!(status.success());
    let list_out = String::from_utf8_lossy(&stdout);
    let mut fprs = Vec::new();
    for line in list_out.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.first() == Some(&"fpr") && parts.len() > 9 {
            // typos:ignore
            if let Some(f) = parts.get(9) {
                fprs.push((*f).to_owned());
            }
        }
    }
    let primary_fpr = fprs.first().expect("found primary fpr").clone();
    let subkey_fpr = fprs.get(1).expect("found subkey fpr").clone();

    let data = b"signed by gpg subkey!";
    let data_file = gpg_home.path().join("data_subkey.txt");
    let sig_file = gpg_home.path().join("data_subkey.sig");
    fs::write(&data_file, data).unwrap();

    let user_arg = format!("{subkey_fpr}!");
    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--detach-sign",
            "-u",
            &user_arg,
            "--output",
            sig_file.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "sign with subkey failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    // Export public armor containing all keys
    let (status, pub_all, _) = run_gpg(
        gpg_home.path(),
        &["--armor", "--export", &primary_fpr],
        None,
    );
    assert!(status.success());

    let kms_uid = kms_import_pgp(&client, &pub_all).await.unwrap();

    let sig_bytes = fs::read(&sig_file).unwrap();
    let verify_resp = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(data.to_vec()),
            signature_data: Some(sig_bytes),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();

    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_armored_detached_signature_verifies() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let (_fpr, _sec, pub_armor) =
        gpg_create_key(gpg_home.path(), "Armored Sig <arm@example.com>", "ed25519");
    let kms_uid = kms_import_pgp(&client, &pub_armor).await.unwrap();

    let data = b"content to verify with armored signature";
    let data_file = gpg_home.path().join("data_arm.txt");
    let sig_file = gpg_home.path().join("data_arm.asc");
    fs::write(&data_file, data).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--armor",
            "--detach-sign",
            "--output",
            sig_file.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --armor --detach-sign failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let armored_sig = fs::read(&sig_file).unwrap();
    let verify_resp = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(data.to_vec()),
            signature_data: Some(armored_sig),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();

    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_armored_message_decrypts() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "Armored Msg <armmsg@example.com>";
    let (_fpr, sec_armor, _pub) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");
    let kms_uid = kms_import_pgp(&client, &sec_armor).await.unwrap();

    let plaintext = b"Top secret payload inside ASCII armor";
    let plain_file = gpg_home.path().join("armplain.txt");
    let cipher_file = gpg_home.path().join("armmsg.asc");
    fs::write(&plain_file, plaintext).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--armor",
            "--trust-model",
            "always",
            "--recipient",
            uid_str,
            "--output",
            cipher_file.to_str().unwrap(),
            "--encrypt",
            plain_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --armor --encrypt failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let armored_cipher = fs::read(&cipher_file).unwrap();
    assert!(String::from_utf8_lossy(&armored_cipher).starts_with("-----BEGIN PGP MESSAGE-----"));

    let dec_resp = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(armored_cipher),
            ..Decrypt::default()
        })
        .await
        .unwrap();

    assert_eq!(
        dec_resp.data.as_deref().map(|v| &v[..]),
        Some(&plaintext[..])
    );
    destroy_key(&client, &kms_uid).await;
}

// ============================================================================
// Direction 2 — Key born in the KMS, used by gpg
// ============================================================================

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_ed25519_gpg_round_trip() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let secret_bytes = kms_export_pgp(&client, &uid, false).await.unwrap();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&secret_bytes));
    assert!(
        status.success(),
        "gpg --import KMS secret key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    // KMS Encrypt -> gpg Decrypt
    let plaintext = b"Hello from KMS Ed25519 to gpg decrypt!";
    let enc_resp = client
        .encrypt(Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
            ..Encrypt::default()
        })
        .await
        .unwrap();
    let ciphertext = enc_resp.data.unwrap();

    let cipher_file = gpg_home.path().join("kms_ed.gpg");
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

    // gpg detach-sign -> KMS SignatureVerify Valid
    let data = b"data to sign with gpg-imported KMS key";
    let data_file = gpg_home.path().join("ed_data.txt");
    let sig_file = gpg_home.path().join("ed_data.sig");
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
        "gpg detach-sign failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let sig_bytes = fs::read(&sig_file).unwrap();
    let verify_resp = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(data.to_vec()),
            signature_data: Some(sig_bytes),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();
    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    destroy_key(&client, &uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_rsa_sizes_gpg_round_trip() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    for size in [2048, 3072, 4096] {
        let gpg_home = create_gpg_home();
        let create_req = pgp_create_request(CryptographicAlgorithm::RSA, Some(size));
        let create_resp = client.create(create_req).await.unwrap();
        let uid = create_resp.unique_identifier.to_string();

        let secret_bytes = kms_export_pgp(&client, &uid, false).await.unwrap();
        let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&secret_bytes));
        assert!(
            status.success(),
            "gpg --import RSA-{size} failed: {}",
            String::from_utf8_lossy(&stderr)
        );

        let plaintext = format!("KMS RSA {size} roundtrip payload").into_bytes();
        let enc_resp = client
            .encrypt(Encrypt {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                data: Some(zeroize::Zeroizing::new(plaintext.clone())),
                ..Encrypt::default()
            })
            .await
            .unwrap();
        let ciphertext = enc_resp.data.unwrap();

        let cipher_file = gpg_home.path().join(format!("rsa_{size}.gpg"));
        fs::write(&cipher_file, &ciphertext).unwrap();

        let (status, stdout, stderr) = run_gpg(
            gpg_home.path(),
            &["--decrypt", cipher_file.to_str().unwrap()],
            None,
        );
        assert!(
            status.success(),
            "gpg --decrypt RSA-{size} failed: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(&stdout[..], &plaintext[..]);

        destroy_key(&client, &uid).await;
    }
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_public_export_is_importable_by_gpg() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let user_id_expected = "Certificate Subject <cert@example.com>";
    let mut create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    create_req.attributes.set_vendor_attribute(
        VENDOR_ID_COSMIAN,
        VENDOR_ATTR_PGP_USER_ID,
        VendorAttributeValue::TextString(user_id_expected.to_owned()),
    );
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let pub_bytes = kms_export_pgp(&client, &uid, true).await.unwrap();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&pub_bytes));
    assert!(
        status.success(),
        "importing KMS public key failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let (status, stdout, _) = run_gpg(gpg_home.path(), &["--list-keys", "--with-colons"], None);
    assert!(status.success());
    let list_out = String::from_utf8_lossy(&stdout);

    let mut pub_count = 0;
    let mut uid_found = false;
    for line in list_out.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.first() == Some(&"pub") {
            pub_count += 1;
        }
        if parts.first() == Some(&"uid")
            && parts.len() > 9
            && parts.get(9).is_some_and(|u| *u == user_id_expected)
        {
            uid_found = true;
        }
    }

    assert_eq!(pub_count, 1, "must show exactly one pub record");
    assert!(
        uid_found,
        "must contain the pgp-user-id vendor attribute: {user_id_expected}"
    );
    destroy_key(&client, &uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_signature_verified_by_gpg_after_public_only_import() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let create_resp = client.create(create_req).await.unwrap();
    let uid = create_resp.unique_identifier.to_string();

    let pub_bytes = kms_export_pgp(&client, &uid, true).await.unwrap();

    let gpg_home = create_gpg_home();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&pub_bytes));
    assert!(
        status.success(),
        "importing public armor into fresh gpg home failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let data = b"payload to sign in KMS and verify with published public cert";
    let sign_resp = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(zeroize::Zeroizing::new(data.to_vec())),
            ..Sign::default()
        })
        .await
        .unwrap();
    let sig_bytes = sign_resp.signature_data.unwrap();

    let sig_file = gpg_home.path().join("pub_test.sig");
    let data_file = gpg_home.path().join("pub_test.txt");
    fs::write(&sig_file, &sig_bytes).unwrap();
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
        "gpg --verify with public cert failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    destroy_key(&client, &uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_gpg_cannot_decrypt_with_wrong_key() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    // Create keys A and B
    let create_a = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid_a = client
        .create(create_a)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    let create_b = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid_b = client
        .create(create_b)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    // Import ONLY key B into gpg
    let sec_b = kms_export_pgp(&client, &uid_b, false).await.unwrap();
    let (status, _, stderr) = run_gpg(gpg_home.path(), &["--import"], Some(&sec_b));
    assert!(
        status.success(),
        "failed to import B: {}",
        String::from_utf8_lossy(&stderr)
    );

    // Encrypt payload to key A
    let plaintext = b"Strictly for key A";
    let enc_resp = client
        .encrypt(Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_a.clone())),
            data: Some(zeroize::Zeroizing::new(plaintext.to_vec())),
            ..Encrypt::default()
        })
        .await
        .unwrap();
    let cipher_a = enc_resp.data.unwrap();

    let cipher_file = gpg_home.path().join("cipher_a.gpg");
    fs::write(&cipher_file, &cipher_a).unwrap();

    // gpg --decrypt with only B imported must fail
    let (status, _, _) = run_gpg(
        gpg_home.path(),
        &["--decrypt", cipher_file.to_str().unwrap()],
        None,
    );
    assert!(
        !status.success(),
        "gpg with key B must fail to decrypt message for key A"
    );

    // KMS Decrypt with key B must also fail
    let dec_res = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid_b.clone())),
            data: Some(cipher_a),
            ..Decrypt::default()
        })
        .await;
    assert!(
        dec_res.is_err(),
        "KMS Decrypt under key B must return Err for key A ciphertext"
    );

    destroy_key(&client, &uid_a).await;
    destroy_key(&client, &uid_b).await;
}

// ============================================================================
// Direction 3 — Frozen-limit pinning (negative tests)
// ============================================================================

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_rejects_inline_signature() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "Inline Signer <in@example.com>";
    let (_fpr, _sec, pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");
    let kms_uid = kms_import_pgp(&client, &pub_armor).await.unwrap();

    let data = b"payload to be signed inline";
    let data_file = gpg_home.path().join("inline_data.txt");
    let inline_out = gpg_home.path().join("inline_msg.gpg");
    fs::write(&data_file, data).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--sign",
            "--output",
            inline_out.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --sign failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let inline_bytes = fs::read(&inline_out).unwrap();
    let verify_res = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(data.to_vec()),
            signature_data: Some(inline_bytes),
            ..SignatureVerify::default()
        })
        .await;

    assert!(
        verify_res.is_err(),
        "inline signature must be rejected with Err (only detached signatures supported)"
    );
    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_kms_rejects_cleartext_signature() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "Clear Signer <clear@example.com>";
    let (_fpr, _sec, pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");
    let kms_uid = kms_import_pgp(&client, &pub_armor).await.unwrap();

    let data = b"payload to be clearsigned";
    let data_file = gpg_home.path().join("clear_data.txt");
    let clear_out = gpg_home.path().join("clear_msg.asc");
    fs::write(&data_file, data).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--clearsign",
            "--output",
            clear_out.to_str().unwrap(),
            data_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --clearsign failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let clear_bytes = fs::read(&clear_out).unwrap();
    let verify_res = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(data.to_vec()),
            signature_data: Some(clear_bytes),
            ..SignatureVerify::default()
        })
        .await;

    assert!(
        verify_res.is_err(),
        "cleartext signature must be rejected with Err (only detached signatures supported)"
    );
    destroy_key(&client, &kms_uid).await;
}

#[tokio::test]
async fn test_pgp_sign_rejects_digested_data() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid = client
        .create(create_req)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    let digest = vec![0x42; 32];
    let sign_res = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            digested_data: Some(digest),
            ..Sign::default()
        })
        .await;

    assert!(sign_res.is_err(), "Sign with digested_data must fail");
    let err_msg = sign_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("require the full data, not a digest"),
        "error must mention full data required, got: {err_msg}"
    );

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_sign_rejects_streaming() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid = client
        .create(create_req)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    // Sign with init_indicator
    let sign_res = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(zeroize::Zeroizing::new(b"chunk".to_vec())),
            init_indicator: Some(true),
            ..Sign::default()
        })
        .await;
    assert!(sign_res.is_err(), "Sign with init_indicator must fail");
    let err_msg = sign_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("streaming is not supported"),
        "error must state streaming is not supported, got: {err_msg}"
    );

    // SignatureVerify with correlation_value
    let verify_res = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(b"chunk".to_vec()),
            signature_data: Some(b"sig".to_vec()),
            correlation_value: Some(b"corr-123".to_vec()),
            ..SignatureVerify::default()
        })
        .await;
    assert!(
        verify_res.is_err(),
        "SignatureVerify with correlation_value must fail"
    );
    let v_err = verify_res.unwrap_err().to_string();
    assert!(
        v_err.contains("streaming is not supported"),
        "error must state streaming is not supported, got: {v_err}"
    );

    destroy_key(&client, &uid).await;
}

#[tokio::test]
async fn test_pgp_wrapped_export_rejects_format_request() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create an AES-256 KEK
    let kek_req = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::WrapKey | CryptographicUsageMask::UnwrapKey,
            ),
            activation_date: Some(time_normalize().unwrap()),
            ..Attributes::default()
        },
        protection_storage_masks: None,
    };
    let kek_resp = client.create(kek_req).await.unwrap();
    let kek_id = kek_resp.unique_identifier.to_string();

    // Attempt to create a PGP key wrapped with KEK.
    // The server's `wrap_object` defaults to `NoEncoding` for keys with key_bytes,
    // which `key_data_to_wrap` does not support for ObjectType::PGPKey.
    // This pins the server-side limitation that PGPKey cannot be wrapped on Create.
    let mut pgp_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    pgp_req
        .attributes
        .set_wrapping_key_id(VENDOR_ID_COSMIAN, &kek_id);
    let create_res = client.create(pgp_req).await;
    assert!(
        create_res.is_err(),
        "PGPKey wrap-on-create must return an error due to unsupported encoding"
    );

    destroy_key(&client, &kek_id).await;
}

#[tokio::test]
async fn test_pgp_create_rejects_unsupported_algorithm() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let mut req = pgp_create_request(CryptographicAlgorithm::AES, Some(256));
    req.attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::AES);
    let res = client.create(req).await;

    assert!(res.is_err(), "creating PGP key with AES must fail");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("not supported for algorithm"),
        "error must mention algorithm not supported, got: {err}"
    );
}

#[tokio::test]
async fn test_pgp_create_rejects_bad_rsa_length() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let req = pgp_create_request(CryptographicAlgorithm::RSA, Some(1024));
    let res = client.create(req).await;

    assert!(
        res.is_err(),
        "creating RSA PGP key with 1024 bits must fail"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("2048, 3072, or 4096"),
        "error must name accepted sizes, got: {err}"
    );
}

#[tokio::test]
async fn test_tampered_detached_signature_is_invalid() {
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid = client
        .create(create_req)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    let data = b"authentic data payload";
    let sign_resp = client
        .sign(Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(zeroize::Zeroizing::new(data.to_vec())),
            ..Sign::default()
        })
        .await
        .unwrap();
    let sig_bytes = sign_resp.signature_data.unwrap();

    // Flip one byte of data
    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0xFF;

    let verify_resp = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(tampered_data),
            signature_data: Some(sig_bytes),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();

    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Invalid),
        "tampered data must yield ValidityIndicator::Invalid, NOT an Err"
    );

    destroy_key(&client, &uid).await;
}

// ============================================================================
// Direction 4 — PGP/MIME (RFC 3156), gpg -> KMS only
// ============================================================================

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_pgp_mime_encrypted_mail_decrypted_by_kms() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "Mail Recipient <mail@example.com>";
    let (_fpr, sec_armor, _pub) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");
    let kms_uid = kms_import_pgp(&client, &sec_armor).await.unwrap();

    // Inner MIME body
    let inner_mime = b"Content-Type: text/plain; charset=utf-8\r\n\r\nHello Alice, this is an RFC 3156 encrypted email.\r\n";
    let inner_file = gpg_home.path().join("inner.mime");
    let enc_file = gpg_home.path().join("inner.asc");
    fs::write(&inner_file, inner_mime).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--armor",
            "--trust-model",
            "always",
            "--recipient",
            uid_str,
            "--output",
            enc_file.to_str().unwrap(),
            "--encrypt",
            inner_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --armor --encrypt inner MIME failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let armored_part = fs::read_to_string(&enc_file).unwrap();

    // Assemble RFC 3156 multipart/encrypted envelope
    let boundary = "boundary42";
    let rfc3156_envelope = format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n\
        --{boundary}\r\n\
        Content-Type: application/pgp-encrypted\r\n\r\n\
        Version: 1\r\n\r\n\
        --{boundary}\r\n\
        Content-Type: application/octet-stream\r\n\r\n\
        {armored_part}\r\n\
        --{boundary}--\r\n"
    );

    // Split on boundary in test to feed part 2 to KMS Decrypt
    let boundary_delimiter = format!("--{boundary}");
    let parts: Vec<&str> = rfc3156_envelope.split(&boundary_delimiter).collect();
    // parts[0] is preamble/headers, parts[1] is control part (Version: 1), parts[2] is payload
    assert!(parts.len() >= 3);
    let payload_part = parts[2];
    let payload_body = payload_part
        .find("\r\n\r\n")
        .map_or(payload_part, |idx| &payload_part[idx + 4..]);
    let pgp_message = payload_body.trim().as_bytes();

    let dec_resp = client
        .decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(pgp_message.to_vec()),
            ..Decrypt::default()
        })
        .await
        .unwrap();

    let decrypted = dec_resp.data.expect("decrypted inner MIME");
    assert_eq!(
        &decrypted[..],
        inner_mime,
        "inner MIME must round-trip byte-for-byte"
    );

    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_pgp_mime_signed_mail_verified_by_kms() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let uid_str = "MIME Signer <mimesign@example.com>";
    let (_fpr, _sec, pub_armor) = gpg_create_key(gpg_home.path(), uid_str, "ed25519");
    let kms_uid = kms_import_pgp(&client, &pub_armor).await.unwrap();

    // Canonical MIME part per RFC 3156 §5 (CRLF line endings)
    let signed_part = b"Content-Type: text/plain; charset=utf-8\r\n\r\nThis is a signed message body per RFC 3156.\r\n";
    let body_file = gpg_home.path().join("signed_body.mime");
    let sig_file = gpg_home.path().join("body.asc");
    fs::write(&body_file, signed_part).unwrap();

    let (status, _, stderr) = run_gpg(
        gpg_home.path(),
        &[
            "--armor",
            "--detach-sign",
            "--output",
            sig_file.to_str().unwrap(),
            body_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        status.success(),
        "gpg --armor --detach-sign MIME body failed: {}",
        String::from_utf8_lossy(&stderr)
    );

    let armored_sig = fs::read_to_string(&sig_file).unwrap();

    // Assemble RFC 3156 multipart/signed envelope
    let boundary = "signed_boundary_99";
    let envelope = format!(
        "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"{boundary}\"\r\n\r\n\
        --{boundary}\r\n\
        {}\
        --{boundary}\r\n\
        Content-Type: application/pgp-signature\r\n\r\n\
        {}\r\n\
        --{boundary}--\r\n",
        String::from_utf8_lossy(signed_part),
        armored_sig.trim()
    );

    // Split and feed part 1 and part 2 to KMS SignatureVerify
    let boundary_delimiter = format!("--{boundary}");
    let count = envelope.split(&boundary_delimiter).count();
    assert!(count >= 3);
    // part 1 contains the exact signed part bytes
    let verify_resp = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(signed_part.to_vec()),
            signature_data: Some(armored_sig.into_bytes()),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();
    assert_eq!(
        verify_resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    // Tamper with one byte of signed_part => Invalid
    let mut tampered_part = signed_part.to_vec();
    tampered_part[0] ^= 0x20;
    let verify_tampered = client
        .signature_verify(SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(kms_uid.clone())),
            data: Some(tampered_part),
            signature_data: Some(fs::read(&sig_file).unwrap()),
            ..SignatureVerify::default()
        })
        .await
        .unwrap();
    assert_eq!(
        verify_tampered.validity_indicator,
        Some(ValidityIndicator::Invalid)
    );

    destroy_key(&client, &kms_uid).await;
}

#[cfg_attr(
    target_os = "windows",
    ignore = "GnuPG integration is supported on Linux/macOS only"
)]
#[tokio::test]
async fn test_pgp_mime_kms_ciphertext_is_binary() {
    let Some(_gpg) = gpg_bin() else {
        println!("gpg not found, skipping");
        return;
    };
    init_test_logging();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let gpg_home = create_gpg_home();

    let create_req = pgp_create_request(CryptographicAlgorithm::Ed25519, None);
    let uid = client
        .create(create_req)
        .await
        .unwrap()
        .unique_identifier
        .to_string();

    let sec_bytes = kms_export_pgp(&client, &uid, false).await.unwrap();
    run_gpg(gpg_home.path(), &["--import"], Some(&sec_bytes));

    let mime_part = b"Content-Type: text/plain\r\n\r\nBinary test MIME payload\r\n";
    let enc_resp = client
        .encrypt(Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            data: Some(zeroize::Zeroizing::new(mime_part.to_vec())),
            ..Encrypt::default()
        })
        .await
        .unwrap();
    let ciphertext = enc_resp.data.unwrap();

    // Executable assertion: output is NOT ASCII armored (does not start with -----BEGIN)
    assert!(
        !ciphertext.starts_with(b"-----BEGIN"),
        "KMS OpenPGP Encrypt output must be binary packets, not ASCII armor"
    );

    // gpg --decrypt directly handles the raw binary output
    let bin_file = gpg_home.path().join("mime_bin.gpg");
    fs::write(&bin_file, &ciphertext).unwrap();

    let (status, stdout, stderr) = run_gpg(
        gpg_home.path(),
        &["--decrypt", bin_file.to_str().unwrap()],
        None,
    );
    assert!(
        status.success(),
        "gpg --decrypt of binary KMS ciphertext failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(&stdout[..], mime_part);

    destroy_key(&client, &uid).await;
}
