use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_client::cosmian_kmip::crypto::elliptic_curves::operation::create_x25519_key_pair;
use cosmian_kms_client::cosmian_kmip::{
    crypto::{symmetric::create_symmetric_key_kmip_object, wrap::unwrap_key_block},
    kmip::{
        kmip_objects::Object,
        kmip_types::{
            CryptographicAlgorithm, CryptographicUsageMask, LinkType, UniqueIdentifier,
            WrappingMethod,
        },
    },
};
use tempfile::TempDir;
use tracing::debug;

use crate::{
    actions::shared::utils::{read_object_from_json_ttlv_file, write_kmip_object_to_file},
    error::CliError,
    tests::{
        cover_crypt::master_key_pair::create_cc_master_key_pair,
        elliptic_curve,
        shared::{export::export_key, import::import_key},
        symmetric,
        utils::{start_default_test_kms_server, ONCE},
    },
};

#[tokio::test]
pub async fn test_import_export_wrap_rfc_5649() -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    // Generate a symmetric wrapping key
    let wrap_key_path = tmp_path.join("wrap.key");
    let mut rng = CsRng::from_entropy();
    let mut wrap_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut wrap_key_bytes);
    let wrap_key = create_symmetric_key_kmip_object(&wrap_key_bytes, CryptographicAlgorithm::AES);
    write_kmip_object_to_file(&wrap_key, &wrap_key_path)?;

    // import the wrapping key
    println!("importing wrapping key");
    let wrap_key_uid = import_key(
        &ctx.owner_cli_conf_path,
        "sym",
        wrap_key_path.to_str().unwrap(),
        None,
        None,
        &[],
        false,
        false,
    )?;

    // test CC
    println!("testing Covercrypt keys");
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "cc",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    // test ec
    println!("testing ec keys");
    let (private_key_id, _public_key_id) = elliptic_curve::create_key_pair::create_ec_key_pair(
        &ctx.owner_cli_conf_path,
        "nist-p256",
        &[],
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    // test sym
    println!("testing symmetric keys");
    let key_id = symmetric::create_key::create_symmetric_key(
        &ctx.owner_cli_conf_path,
        None,
        None,
        None,
        &[] as &[&str],
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "sym",
        &key_id,
        &wrap_key_uid,
        &wrap_key,
    )?;

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
pub async fn test_import_export_wrap_ecies() -> Result<(), CliError> {
    // log_init("debug");
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;
    // Generate a symmetric wrapping key
    let wrap_private_key_uid = "wrap_private_key_uid";
    let wrap_public_key_uid = "wrap_public_key_uid";
    let wrap_key_pair = create_x25519_key_pair(
        wrap_private_key_uid,
        wrap_public_key_uid,
        Some(CryptographicAlgorithm::EC),
        Some(CryptographicUsageMask::Decrypt),
        Some(CryptographicUsageMask::Encrypt),
    )?;
    // Write the private key to a file and import it
    let wrap_private_key_path = tmp_path.join("wrap.private.key");
    write_kmip_object_to_file(wrap_key_pair.private_key(), &wrap_private_key_path)?;
    import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        wrap_private_key_path.to_str().unwrap(),
        None,
        Some(wrap_private_key_uid.to_string()),
        &[],
        false,
        true,
    )?;
    // Write the public key to a file and import it
    let wrap_public_key_path = tmp_path.join("wrap.public.key");
    write_kmip_object_to_file(wrap_key_pair.public_key(), &wrap_public_key_path)?;
    import_key(
        &ctx.owner_cli_conf_path,
        "ec",
        wrap_public_key_path.to_str().unwrap(),
        None,
        Some(wrap_public_key_uid.to_string()),
        &[],
        false,
        true,
    )?;

    // test CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &ctx.owner_cli_conf_path,
        "--policy-specifications",
        "test_data/policy_specifications.json",
        &[],
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "cc",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;

    debug!("testing EC keys");
    let (private_key_id, _public_key_id) = elliptic_curve::create_key_pair::create_ec_key_pair(
        &ctx.owner_cli_conf_path,
        "nist-p256",
        &[],
    )?;
    test_import_export_wrap_private_key(
        &ctx.owner_cli_conf_path,
        "ec",
        &private_key_id,
        wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )?;

    debug!("testing symmetric keys");
    let key_id = symmetric::create_key::create_symmetric_key(
        &ctx.owner_cli_conf_path,
        None,
        None,
        None,
        &[] as &[&str],
    )?;
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
    export_key(
        cli_conf_path,
        sub_command,
        private_key_id,
        private_key_file.to_str().unwrap(),
        None,
        false,
        None,
        false,
    )?;
    let private_key = read_object_from_json_ttlv_file(&private_key_file)?;

    // Export the private key with wrapping
    let wrapped_private_key_file = tmp_path.join("wrapped_master_private.key");
    export_key(
        cli_conf_path,
        sub_command,
        private_key_id,
        wrapped_private_key_file.to_str().unwrap(),
        None,
        false,
        Some(wrapping_key_uid.to_string()),
        false,
    )?;

    // test the exported private key with wrapping
    {
        let mut wrapped_private_key = read_object_from_json_ttlv_file(&wrapped_private_key_file)?;
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
            UniqueIdentifier::TextString(wrapping_key_uid.to_owned())
        );
        assert!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .cryptographic_parameters
                .is_none()
        );
        unwrap_key_block(wrapped_private_key.key_block_mut()?, unwrapping_key)?;
        assert_eq!(
            wrapped_private_key.key_block()?.key_value,
            private_key.key_block()?.key_value
        );
    }

    // test the unwrapping on import
    {
        // import the wrapped key, unwrapping it on import
        let unwrapped_key_id = import_key(
            cli_conf_path,
            sub_command,
            wrapped_private_key_file.to_str().unwrap(),
            None,
            None,
            &[],
            true,
            true,
        )?;
        // re-export it as registered and check it was correctly unwrapped
        let re_exported_key_file = tmp_path.join("re_exported_master_private.key");
        export_key(
            cli_conf_path,
            sub_command,
            &unwrapped_key_id,
            re_exported_key_file.to_str().unwrap(),
            None,
            false,
            None,
            false,
        )?;
        let re_exported_key = read_object_from_json_ttlv_file(&re_exported_key_file)?;
        assert_eq!(
            re_exported_key.key_block()?.key_value.key_material,
            private_key.key_block()?.key_value.key_material
        );
        assert_eq!(
            re_exported_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink),
            private_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink)
        );
        assert!(re_exported_key.key_wrapping_data().is_none());
    }

    // test the unwrapping on export
    {
        // import the wrapped key, un wrapping it on import
        let wrapped_key_id = import_key(
            cli_conf_path,
            sub_command,
            wrapped_private_key_file.to_str().unwrap(),
            None,
            None,
            &[],
            false,
            true,
        )?;
        // re-export it as registered and check it was correctly unwrapped
        let exported_unwrapped_key_file = tmp_path.join("exported_unwrapped_master_private.key");
        export_key(
            cli_conf_path,
            sub_command,
            &wrapped_key_id,
            exported_unwrapped_key_file.to_str().unwrap(),
            None,
            true,
            None,
            false,
        )?;
        let exported_unwrapped_key = read_object_from_json_ttlv_file(&exported_unwrapped_key_file)?;
        assert_eq!(
            exported_unwrapped_key.key_block()?.key_value,
            private_key.key_block()?.key_value
        );
        assert!(exported_unwrapped_key.key_wrapping_data().is_none());
    }

    Ok(())
}
