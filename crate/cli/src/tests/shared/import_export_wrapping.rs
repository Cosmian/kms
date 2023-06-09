use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{CryptographicAlgorithm, WrappingMethod},
};
use cosmian_kms_utils::crypto::{
    curve_25519::operation::create_ec_key_pair, symmetric::create_symmetric_key,
    wrap::decrypt_bytes,
};
use tempfile::TempDir;

use crate::{
    actions::shared::utils::{read_key_from_file, write_kmip_object_to_file},
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        elliptic_curve,
        shared::{export::export, import::import},
        symmetric,
        utils::{init_test_server, ONCE},
    },
};

#[tokio::test]
pub async fn test_import_export_wrap_rfc_5649() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_init(init_test_server).await;
    // Generate a symmetric wrapping key
    let wrap_key_path = tmp_path.join("wrap.key");
    let mut rng = CsRng::from_entropy();
    let mut wrap_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut wrap_key_bytes);
    let wrap_key = create_symmetric_key(&wrap_key_bytes, CryptographicAlgorithm::AES);
    write_kmip_object_to_file(&wrap_key, &wrap_key_path)?;
    let wrap_key_uid = import(
        &ctx.owner_cli_conf_path,
        "sym",
        wrap_key_path.to_str().unwrap(),
        None,
        false,
        false,
    )?;

    // test CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "cc",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;
    // test ec
    let (private_key_id, _public_key_id) =
        elliptic_curve::create_key_pair::create_ec_key_pair(&ctx.owner_cli_conf_path)?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;
    // test sym
    let key_id =
        symmetric::create_key::create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None)?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    Ok(())
}

#[tokio::test]
pub async fn test_import_export_wrap_ecies() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_init(init_test_server).await;
    // Generate a symmetric wrapping key
    let mut rng = CsRng::from_entropy();
    let wrap_private_key_uid = "wrap_private_key_uid";
    let wrap_public_key_uid = "wrap_public_key_uid";
    let wrap_key_pair = create_ec_key_pair(&mut rng, wrap_private_key_uid, wrap_public_key_uid)?;
    // Write the private key to a file
    let wrap_private_key_path = tmp_path.join("wrap.private.key");
    write_kmip_object_to_file(wrap_key_pair.private_key(), &wrap_private_key_path)?;
    import(
        &ctx.owner_cli_conf_path,
        "ec",
        wrap_private_key_path.to_str().unwrap(),
        Some(wrap_private_key_uid.to_string()),
        false,
        true,
    )?;
    // Write the public key to a file
    let wrap_public_key_path = tmp_path.join("wrap.public.key");
    write_kmip_object_to_file(wrap_key_pair.public_key(), &wrap_public_key_path)?;
    import(
        &ctx.owner_cli_conf_path,
        "ec",
        wrap_public_key_path.to_str().unwrap(),
        Some(wrap_public_key_uid.to_string()),
        false,
        true,
    )?;
    // test CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "cc",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;
    // test ec
    let (private_key_id, _public_key_id) =
        elliptic_curve::create_key_pair::create_ec_key_pair(&ctx.owner_cli_conf_path)?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;
    // test sym
    let key_id =
        symmetric::create_key::create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None)?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;
    Ok(())
}

fn test_import_export_wrap_private_key(
    cli_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
    wrapping_key_uid: &str,
    unwrapping_key: &Object,
) -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Export the private key without wrapping
    let private_key_file = tmp_path.join("master_private.key");
    export(
        cli_conf_path,
        sub_command,
        private_key_id,
        private_key_file.to_str().unwrap(),
        false,
        false,
        None,
        false,
    )?;
    let private_key = read_key_from_file(&private_key_file)?;

    // Export the private key with wrapping
    let wrapped_private_key_file = tmp_path.join("wrapped_master_private.key");
    export(
        cli_conf_path,
        sub_command,
        private_key_id,
        wrapped_private_key_file.to_str().unwrap(),
        false,
        false,
        Some(wrapping_key_uid.to_string()),
        false,
    )?;

    // test the exported private key with wrapping
    {
        let wrapped_private_key = read_key_from_file(&wrapped_private_key_file)?;
        let wrapped_key_wrapping_data = wrapped_private_key.key_wrapping_data().unwrap();
        assert_eq!(
            wrapped_key_wrapping_data.wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .unique_identifier,
            wrapping_key_uid
        );
        assert!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .cryptographic_parameters
                .is_none()
        );
        let wrapped_key_bytes = wrapped_private_key.key_block()?.key_bytes()?;
        let plaintext = decrypt_bytes(unwrapping_key, &wrapped_key_bytes)?;
        assert_eq!(plaintext, private_key.key_block()?.key_bytes()?);
    }

    // test the unwrapping on import
    {
        // import the wrapped key, un wrapping it on import
        let unwrapped_key_id = import(
            cli_conf_path,
            sub_command,
            wrapped_private_key_file.to_str().unwrap(),
            None,
            true,
            true,
        )?;
        // re-export it as registered and check it was correctly unwrapped
        let re_exported_key_file = tmp_path.join("re_exported_master_private.key");
        export(
            cli_conf_path,
            sub_command,
            &unwrapped_key_id,
            re_exported_key_file.to_str().unwrap(),
            false,
            false,
            None,
            false,
        )?;
        let re_exported_key = read_key_from_file(&re_exported_key_file)?;
        assert_eq!(
            re_exported_key.key_block()?.key_bytes()?,
            private_key.key_block()?.key_bytes()?
        );
        assert!(re_exported_key.key_wrapping_data().is_none());
    }

    // test the unwrapping on export
    {
        // import the wrapped key, un wrapping it on import
        let wrapped_key_id = import(
            cli_conf_path,
            sub_command,
            wrapped_private_key_file.to_str().unwrap(),
            None,
            false,
            true,
        )?;
        // re-export it as registered and check it was correctly unwrapped
        let exported_unwrapped_key_file = tmp_path.join("exported_unwrapped_master_private.key");
        export(
            cli_conf_path,
            sub_command,
            &wrapped_key_id,
            exported_unwrapped_key_file.to_str().unwrap(),
            false,
            true,
            None,
            false,
        )?;
        let exported_unwrapped_key = read_key_from_file(&exported_unwrapped_key_file)?;
        assert_eq!(
            exported_unwrapped_key.key_block()?.key_bytes()?,
            private_key.key_block()?.key_bytes()?
        );
        assert!(exported_unwrapped_key.key_wrapping_data().is_none());
    }

    Ok(())
}
