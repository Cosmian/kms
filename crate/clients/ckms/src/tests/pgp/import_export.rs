use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use cosmian_kms_cli_actions::actions::pgp::keys::create_key::{CreatePgpKeyAction, PgpAlgorithm};
use tempfile::{NamedTempFile, TempDir};
use test_kms_server::start_default_test_kms_server;

use super::{SUB_COMMAND, create_key::create_pgp_key};
use crate::{
    config::CKMS_CONF_ENV,
    error::result::CosmianResult,
    tests::utils::{ckms_bin, owner_config, recover_cmd_logs},
};

#[tokio::test]
async fn test_pgp_export_secret_and_public() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Export Test <export@example.com>".to_owned()),
        ..Default::default()
    };
    let uid = create_pgp_key(&cli_conf_path, &action)?;

    let secret_file = NamedTempFile::new()?;
    let secret_path = secret_file.path().to_str().unwrap();

    // Export secret key
    let mut cmd_sec = ckms_bin();
    cmd_sec.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &uid,
        "--key-format",
        "pgp-secret",
        secret_path,
    ]);
    let out_sec = recover_cmd_logs(&mut cmd_sec);
    assert!(
        out_sec.status.success(),
        "export secret failed: {}",
        String::from_utf8_lossy(&out_sec.stderr)
    );

    let secret_bytes = fs::read(secret_path)?;
    let secret_str = String::from_utf8(secret_bytes)?;
    assert!(
        secret_str.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "secret key did not start with expected header: {secret_str}"
    );

    // Export public key
    let public_file = NamedTempFile::new()?;
    let public_path = public_file.path().to_str().unwrap();

    let mut cmd_pub = ckms_bin();
    cmd_pub.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &uid,
        "--key-format",
        "pgp-public",
        public_path,
    ]);
    let out_pub = recover_cmd_logs(&mut cmd_pub);
    assert!(
        out_pub.status.success(),
        "export public failed: {}",
        String::from_utf8_lossy(&out_pub.stderr)
    );

    let public_bytes = fs::read(public_path)?;
    let public_str = String::from_utf8(public_bytes)?;
    assert!(
        public_str.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "public key did not start with expected header: {public_str}"
    );

    Ok(())
}

#[tokio::test]
async fn test_pgp_import_roundtrip() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);

    let action = CreatePgpKeyAction {
        algorithm: PgpAlgorithm::Ed25519,
        user_id: Some("Import Roundtrip <import@example.com>".to_owned()),
        ..Default::default()
    };
    let orig_uid = create_pgp_key(&cli_conf_path, &action)?;

    // Export public key
    let pub_file1 = NamedTempFile::new()?;
    let pub_path1 = pub_file1.path().to_str().unwrap();

    let mut cmd_exp1 = ckms_bin();
    cmd_exp1.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &orig_uid,
        "--key-format",
        "pgp-public",
        pub_path1,
    ]);
    let out_exp1 = recover_cmd_logs(&mut cmd_exp1);
    assert!(out_exp1.status.success());

    let pub_bytes1 = fs::read(pub_path1)?;

    // Import under a new id
    let new_uid = format!("pgp-imported-{}", uuid::Uuid::new_v4());
    let mut cmd_imp = ckms_bin();
    cmd_imp.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "import",
        "--key-format",
        "pgp",
        pub_path1,
        &new_uid,
    ]);
    let out_imp = recover_cmd_logs(&mut cmd_imp);
    assert!(
        out_imp.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out_imp.stderr)
    );

    // Re-export public key from new UID
    let pub_file2 = NamedTempFile::new()?;
    let pub_path2 = pub_file2.path().to_str().unwrap();

    let mut cmd_exp2 = ckms_bin();
    cmd_exp2.env(CKMS_CONF_ENV, &cli_conf_path).args([
        SUB_COMMAND,
        "export",
        "-k",
        &new_uid,
        "--key-format",
        "pgp-public",
        pub_path2,
    ]);
    let out_exp2 = recover_cmd_logs(&mut cmd_exp2);
    assert!(out_exp2.status.success());

    let pub_bytes2 = fs::read(pub_path2)?;
    assert_eq!(
        pub_bytes1, pub_bytes2,
        "exported public keys before and after import roundtrip must match"
    );

    Ok(())
}

fn run_gpg(home: &Path, args: &[&str], stdin_data: Option<&[u8]>) -> Output {
    let mut command = Command::new("gpg");
    command
        .env("GNUPGHOME", ".")
        .current_dir(home)
        .args([
            "--batch",
            "--yes",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ])
        .args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .expect("gpg should be available for OpenPGP tests");
    if let Some(input) = stdin_data {
        child
            .stdin
            .take()
            .expect("GnuPG stdin is piped when input is provided")
            .write_all(input)
            .expect("write GnuPG input");
    }
    child.wait_with_output().expect("wait for GnuPG")
}

#[tokio::test]
async fn test_gpg_key_import_export_accepts_armored_and_binary_keys() -> CosmianResult<()> {
    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("gpg not found, skipping GnuPG key format test");
        return Ok(());
    }

    let ctx = start_default_test_kms_server().await;
    let cli_conf_path = owner_config(ctx);
    let gpg_home = TempDir::new()?;
    let user_id = "CKMS GnuPG Format Test <gpg-format@example.com>";

    let generated = run_gpg(
        gpg_home.path(),
        &["--quick-generate-key", user_id, "ed25519", "sign", "0"],
        None,
    );
    assert!(
        generated.status.success(),
        "GnuPG key generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let secret_armored = run_gpg(
        gpg_home.path(),
        &["--armor", "--export-secret-keys", user_id],
        None,
    );
    let secret_binary = run_gpg(gpg_home.path(), &["--export-secret-keys", user_id], None);
    let public_armored = run_gpg(gpg_home.path(), &["--armor", "--export", user_id], None);
    let public_binary = run_gpg(gpg_home.path(), &["--export", user_id], None);
    for export in [
        &secret_armored,
        &secret_binary,
        &public_armored,
        &public_binary,
    ] {
        assert!(
            export.status.success() && !export.stdout.is_empty(),
            "GnuPG key export failed: {}",
            String::from_utf8_lossy(&export.stderr)
        );
    }

    for (format_name, bytes, is_secret) in [
        ("secret-armored", &secret_armored.stdout, true),
        ("secret-binary", &secret_binary.stdout, true),
        ("public-armored", &public_armored.stdout, false),
        ("public-binary", &public_binary.stdout, false),
    ] {
        let input = NamedTempFile::new()?;
        fs::write(input.path(), bytes)?;
        let imported_uid = format!("gpg-{format_name}-{}", uuid::Uuid::new_v4());

        let mut import = ckms_bin();
        import.env(CKMS_CONF_ENV, &cli_conf_path).args([
            SUB_COMMAND,
            "import",
            "--key-format",
            "pgp",
            input.path().to_str().unwrap(),
            &imported_uid,
        ]);
        let import_output = recover_cmd_logs(&mut import);
        assert!(
            import_output.status.success(),
            "CKMS import of {format_name} GnuPG key failed: {}",
            String::from_utf8_lossy(&import_output.stderr)
        );

        let output_formats = if is_secret {
            [("pgp-secret", true), ("pgp-secret-binary", false)]
        } else {
            [("pgp-public", true), ("pgp-public-binary", false)]
        };

        for (output_format, is_armored) in output_formats {
            let output = NamedTempFile::new()?;
            let mut export = ckms_bin();
            export.env(CKMS_CONF_ENV, &cli_conf_path).args([
                SUB_COMMAND,
                "export",
                "-k",
                &imported_uid,
                "--key-format",
                output_format,
                output.path().to_str().unwrap(),
            ]);
            let export_output = recover_cmd_logs(&mut export);
            assert!(
                export_output.status.success(),
                "CKMS export of {format_name} GnuPG key as {output_format} failed: {}",
                String::from_utf8_lossy(&export_output.stderr)
            );

            let exported_bytes = fs::read(output.path())?;
            let armor_header = if is_secret {
                b"-----BEGIN PGP PRIVATE KEY BLOCK-----".as_slice()
            } else {
                b"-----BEGIN PGP PUBLIC KEY BLOCK-----".as_slice()
            };
            assert_eq!(
                exported_bytes.starts_with(armor_header),
                is_armored,
                "CKMS export format {output_format} did not match the requested encoding"
            );

            let roundtrip_home = TempDir::new()?;
            let exported_bytes = fs::read(output.path())?;
            let gpg_import = run_gpg(roundtrip_home.path(), &["--import"], Some(&exported_bytes));
            assert!(
                gpg_import.status.success(),
                "GnuPG could not import CKMS {output_format} export of {format_name} key: {}",
                String::from_utf8_lossy(&gpg_import.stderr)
            );
            let list_arg = if is_secret {
                "--list-secret-keys"
            } else {
                "--list-keys"
            };
            let listed = run_gpg(roundtrip_home.path(), &[list_arg, user_id], None);
            assert!(
                listed.status.success(),
                "GnuPG did not retain the CKMS {output_format} export of {format_name} key: {}",
                String::from_utf8_lossy(&listed.stderr)
            );

            let reimported_uid = format!("ckms-{output_format}-{}", uuid::Uuid::new_v4());
            let mut reimport = ckms_bin();
            reimport.env(CKMS_CONF_ENV, &cli_conf_path).args([
                SUB_COMMAND,
                "import",
                "--key-format",
                "pgp",
                output.path().to_str().unwrap(),
                &reimported_uid,
            ]);
            let reimport_output = recover_cmd_logs(&mut reimport);
            assert!(
                reimport_output.status.success(),
                "CKMS could not re-import its {output_format} export of {format_name} key: {}",
                String::from_utf8_lossy(&reimport_output.stderr)
            );
        }
    }

    Ok(())
}
