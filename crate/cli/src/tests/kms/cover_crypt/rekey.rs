use std::path::PathBuf;

use cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::KeyUsage;
use cosmian_kms_crypto::{
    crypto::cover_crypt::access_structure::access_structure_from_json_file,
    reexport::{
        cosmian_cover_crypt::{
            AccessPolicy, MasterSecretKey, UserSecretKey, api::Covercrypt,
            encrypted_header::EncryptedHeader,
        },
        cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, test_serialization},
    },
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        cover_crypt::{
            decrypt::DecryptAction,
            encrypt::EncryptAction,
            keys::{
                create_key_pair::CreateMasterKeyPairAction,
                create_user_key::CreateUserKeyAction,
                rekey::{PruneAction, ReKeyAction},
            },
        },
        shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_rekey_error() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_secret_key_id, _master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };
    let _user_decryption_key = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // bad attributes
    ReKeyAction {
        msk_uid: Some(master_secret_key_id.clone()),
        access_policy: "bad_access_policy".to_string(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // bad keys
    ReKeyAction {
        msk_uid: Some("bad_key".to_string()),
        access_policy: "Department::MKG || Department::FIN".to_string(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // Import a wrapped key

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // create a symmetric key
    let symmetric_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // export a wrapped key
    let exported_wrapped_key_file = tmp_path.join("exported_wrapped_master_private.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(master_secret_key_id.clone()),
        key_file: exported_wrapped_key_file.clone(),
        wrap_key_id: Some(symmetric_key_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // import it wrapped
    let wrapped_key_id = ImportSecretDataOrKeyAction {
        key_file: exported_wrapped_key_file.clone(),
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // Rekeying wrapped keys is not allowed
    ReKeyAction {
        msk_uid: Some(wrapped_key_id.clone()),
        access_policy: "Department::MKG || Department::FIN".to_string(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}

#[test]
fn test_cc() -> KmsCliResult<()> {
    let access_structure = access_structure_from_json_file(&PathBuf::from(
        "../../test_data/access_structure_specifications.json",
    ))?;

    let cover_crypt = Covercrypt::default();
    let (mut msk, _mpk) = cover_crypt.setup()?;
    msk.access_structure = access_structure;
    let mpk = cover_crypt.update_msk(&mut msk)?;
    test_serialization(&msk).unwrap();

    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Top Secret";
    let access_policy = AccessPolicy::parse(access_policy)?;
    let uk = cover_crypt.generate_user_secret_key(&mut msk, &access_policy)?;
    let uk_bytes = uk.serialize()?;
    let uk = UserSecretKey::deserialize(&uk_bytes)?;

    let encryption_policy = "Department::MKG && Security Level::Confidential";
    let ad = Some("myid".as_ref());
    let (_secret, encrypted_header) = EncryptedHeader::generate(
        &cover_crypt,
        &mpk,
        &AccessPolicy::parse(encryption_policy)?,
        None,
        ad,
    )?;
    let encrypted_header = encrypted_header.serialize()?.to_vec();

    let mut de = Deserializer::new(&encrypted_header);
    let encrypted_header = EncryptedHeader::read(&mut de)?;

    let _plaintext_header = encrypted_header.decrypt(&cover_crypt, &uk, ad)?;

    let ap = AccessPolicy::parse("Department::MKG || Department::FIN")?;
    let _mpk = cover_crypt.rekey(&mut msk, &ap)?;

    let msk_bytes = msk.serialize()?;
    let _my_msk = MasterSecretKey::deserialize(&msk_bytes)?;

    Ok(())
}

#[tokio::test]
async fn test_enc_dec_rekey() -> KmsCliResult<()> {
    log_init(None);

    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };
    let user_decryption_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "Department::MKG || Department::FIN".to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG".to_string(),
        key_id: Some(master_public_key_id),
        output_file: Some(output_file_before.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![output_file_before.clone()],
        key_id: Some(user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(user_decryption_key_id),
        key_file: exported_user_decryption_key_file.clone(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // rekey the attributes
    ReKeyAction {
        msk_uid: Some(master_secret_key_id.clone()),
        access_policy: "Department::MKG || Department::FIN".to_string(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_rekey_prune() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let output_file_after = tmp_path.join("plain.after.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };
    let user_decryption_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: Some(master_public_key_id.clone()),
        output_file: Some(output_file_before.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_files: vec![output_file_before.clone()],
        key_id: Some(user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(user_decryption_key_id.clone()),
        key_file: exported_user_decryption_key_file.clone(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // rekey the attributes
    ReKeyAction {
        msk_uid: Some(master_secret_key_id.clone()),
        access_policy: "Department::MKG || Department::FIN".to_string(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // encrypt again after rekeying
    EncryptAction {
        input_files: vec![input_file.clone()],
        encryption_policy: "Department::MKG && Security Level::Confidential".to_string(),
        key_id: Some(master_public_key_id),
        output_file: Some(output_file_after.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the new file
    DecryptAction {
        input_files: vec![output_file_after.clone()],
        key_id: Some(user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    // ... and the old file
    DecryptAction {
        input_files: vec![output_file_before.clone()],
        key_id: Some(user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // import the non rotated user_decryption_key
    let old_user_decryption_key_id = ImportSecretDataOrKeyAction {
        key_file: exported_user_decryption_key_file.clone(),
        replace_existing: false,
        key_usage: Some(vec![KeyUsage::Unrestricted]),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    // the imported user key should not be able to decrypt the new file
    DecryptAction {
        input_files: vec![output_file_after.clone()],
        key_id: Some(old_user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();
    // ... but should decrypt the old file
    DecryptAction {
        input_files: vec![output_file_before.clone()],
        key_id: Some(old_user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // prune the attributes
    PruneAction {
        access_policy: "Department::MKG || Department::FIN".to_string(),
        msk_uid: Some(master_secret_key_id.clone()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the new file
    DecryptAction {
        input_files: vec![output_file_after.clone()],
        key_id: Some(user_decryption_key_id.clone()),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // but no longer the old file
    DecryptAction {
        input_files: vec![output_file_before.clone()],
        key_id: Some(user_decryption_key_id),
        output_file: Some(recovered_file.clone()),
        authentication_data: Some("myid".to_owned()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    Ok(())
}
