use std::convert::TryFrom;

use actix_web::http::StatusCode;
use cosmian_kms::{
    kmip_server::keys::attributes_from_key_block,
    kmip_shared::dmcfe_lwe::{
        lwe_functional_key_create_request, lwe_master_secret_key_create_request,
        lwe_secret_key_create_request, secret_data_from_lwe_functional_key,
        secret_key_from_lwe_fks_secret_key, secret_key_from_lwe_master_secret_key,
        secret_key_from_lwe_secret_key, FunctionalKeyCreateRequest, McfeDecryptionRequest,
        McfeEncryptionRequest,
    },
};
use cosmian_kms_client::kmip::{
    kmip_data_structures::KeyValue,
    kmip_objects::{Object, ObjectType},
    kmip_operations,
    kmip_types::KeyFormatType,
};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;

use crate::prelude::*;

// -----------------------
// LWE Parameters for Secret Keys
// and FKS Secret Keys
// -----------------------

pub fn get_parameters(lwe_setup: &lwe::Setup) -> CResult<lwe::Parameters> {
    let lwe_parameters = lwe::Parameters::instantiate(lwe_setup)
        .map_err(CError::msg)
        .coded(StatusCode::BAD_REQUEST)?;
    Ok(lwe_parameters)
}

pub fn get_fks_parameters(lwe_setup: &lwe::Setup) -> CResult<lwe::Parameters> {
    let lwe_parameters = lwe::Parameters::instantiate(lwe_setup)
        .map_err(CError::msg)
        .coded(StatusCode::BAD_REQUEST)?;
    let lwe_kfs_parameters = lwe_parameters.fks_parameters().map_err(CError::msg)?;
    Ok(lwe_kfs_parameters)
}

// -----------------------
// LWE Master Secret Key
// -----------------------

// Get a Master Secret Key
pub fn get_lwe_master_secret_key(
    uid: &str,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<(lwe::Setup, lwe::MasterSecretKey)> {
    let gr = kms_client.get(&kmip_operations::Get::from(uid))?;
    let object = &gr.object;
    match object {
        Object::SymmetricKey { key_block } => {
            if key_block.key_format_type != KeyFormatType::McfeMasterSecretKey {
                anyhow::bail!(
                    "The key at uid: {} is not an MCFE Lwe Master Secret Key",
                    uid
                );
            }
            let lwe_msk = lwe::MasterSecretKey::try_from(key_block).map_err(CError::msg)?;
            let attributes = match &key_block.key_value {
                KeyValue::PlainText { attributes, .. } => attributes.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("The key at uid: {} is missing its attributes", uid)
                }),
                KeyValue::Wrapped(_) => Err(anyhow::anyhow!(
                    "The key at uid: {} is wrapped and this not yet available",
                    uid
                )),
            }?;
            let setup = lwe::Setup::try_from(attributes).map_err(CError::msg)?;
            Ok((setup, lwe_msk))
        }
        _other => Err(anyhow::anyhow!(
            "The objet at uid: {} is not an MCFE LWE Master Secret Key",
            uid
        )
        .coded(StatusCode::BAD_REQUEST)),
    }
}

pub fn create_lwe_master_secret_key(
    setup: &lwe::Setup,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    let cr = lwe_master_secret_key_create_request(setup).map_err(CError::msg)?;
    kms_client.create(&cr).map(|resp| resp.unique_identifier)
}

pub fn import_lwe_master_secret_key(
    setup: &lwe::Setup,
    msk: &[lwe::SecretKey],
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    check_argument!(
        parameters.clients == msk.len(),
        "The master secret key contains: secret keys for {} clients; {} expected",
        msk.len(),
        parameters.clients
    );
    for (n, sk) in msk.iter().enumerate() {
        check_secret_key(n, &parameters, sk)?;
    }
    let sk = secret_key_from_lwe_master_secret_key(setup, msk)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(true),
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        key_wrap_type: None,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

pub fn update_lwe_master_secret_key(
    setup: &lwe::Setup,
    uid: &str,
    key: &[lwe::SecretKey], // lwe::MasterSecretKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    check_argument!(
        key.len() == parameters.clients,
        "The setup parameters do not match the characteristics of the secret key. Invalid key \
         length",
    );
    for (i, sk_i) in key.iter().enumerate() {
        check_secret_key(i, &parameters, sk_i)?;
    }
    let sk = secret_key_from_lwe_master_secret_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: uid.to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

// -----------------------
// LWE Secret Key
// -----------------------

#[derive(PartialEq, Copy, Clone)]
pub enum LweSecretKeyType {
    Secret,
    FksSecret,
}

// Get a Secret Key or FKS Secret Key
pub fn get_lwe_key(
    uid: &str,
    lwe_key_type: LweSecretKeyType,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<(lwe::Setup, lwe::SecretKey)> {
    let gr = kms_client.get(&kmip_operations::Get::from(uid))?;
    let object = &gr.object;
    match object {
        Object::SymmetricKey { key_block } => {
            if !match &key_block.key_format_type {
                KeyFormatType::McfeFksSecretKey => lwe_key_type == LweSecretKeyType::FksSecret,
                KeyFormatType::McfeSecretKey => lwe_key_type == LweSecretKeyType::Secret,
                _ => false,
            } {
                return Err(anyhow::anyhow!(
                    "The key at uid: {} is not an MCFE Lwe (FKS) Secret Key",
                    uid
                ))
            }
            let lwe_sk = lwe::SecretKey::try_from(key_block).map_err(CError::msg)?;
            let attributes = match &key_block.key_value {
                KeyValue::PlainText { attributes, .. } => attributes.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("The key at uid: {} is missing its attributes", uid)
                }),
                KeyValue::Wrapped(_) => Err(anyhow::anyhow!(
                    "The key at uid: {} is wrapped and this not yet available",
                    uid
                )),
            }?;
            let setup = lwe::Setup::try_from(attributes).map_err(CError::msg)?;
            Ok((setup, lwe_sk))
        }
        _other => Err(anyhow::anyhow!(
            "The objet at uid: {} is not an MCFE LWE (FKS) Secret Key",
            uid
        )
        .coded(StatusCode::BAD_REQUEST)),
    }
}

pub fn create_lwe_secret_key(
    setup: &lwe::Setup,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    let cr = lwe_secret_key_create_request(setup).map_err(CError::msg)?;
    kms_client.create(&cr).map(|resp| resp.unique_identifier)
}

pub fn import_lwe_secret_key(
    setup: &lwe::Setup,
    key: &lwe::SecretKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    check_secret_key(0, &parameters, key)?;
    let sk = secret_key_from_lwe_secret_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

pub fn update_lwe_secret_key(
    setup: &lwe::Setup,
    uid: &str,
    key: &lwe::SecretKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    check_secret_key(0, &parameters, key)?;
    let sk = secret_key_from_lwe_secret_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: uid.to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

// -----------------------
// LWE FKS Secret Key
// -----------------------

pub fn import_lwe_fks_secret_key(
    setup: &lwe::Setup,
    key: &lwe::SecretKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup)
        .map_err(CError::msg)?
        .fks_parameters()
        .map_err(CError::msg)?;
    check_secret_key(0, &parameters, key)?;
    let sk = secret_key_from_lwe_fks_secret_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::SecretData,
        replace_existing: None,
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SecretData, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

pub fn update_lwe_fks_secret_key(
    setup: &lwe::Setup,
    uid: &str,
    key: &lwe::SecretKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    // check that Setup makes sense
    let parameters = lwe::Parameters::instantiate(setup)
        .map_err(CError::msg)?
        .fks_parameters()
        .map_err(CError::msg)?;
    check_secret_key(0, &parameters, key)?;
    let sk = secret_key_from_lwe_fks_secret_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: uid.to_string(),
        object_type: ObjectType::SecretData,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SecretData, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

// -----------------------
// LWE Functional Key
// -----------------------

pub fn get_lwe_functional_key(
    uid: &str,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<(lwe::Setup, lwe::FunctionalKey)> {
    let gr = kms_client.get(&kmip_operations::Get::from(uid))?;
    let object = &gr.object;
    match object {
        Object::SecretData { key_block, .. } => {
            if key_block.key_format_type != KeyFormatType::McfeFunctionalKey {
                return Err(anyhow::anyhow!(
                    "The key at uid: {} is not an MCFE Functional Secret Key",
                    uid
                ))
            }
            let lwe_msk = lwe::FunctionalKey::try_from(key_block).map_err(CError::msg)?;
            let attributes = match &key_block.key_value {
                KeyValue::PlainText { attributes, .. } => attributes.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("The key at uid: {} is missing its attributes", uid)
                }),
                KeyValue::Wrapped(_) => Err(anyhow::anyhow!(
                    "The key at uid: {} is wrapped and this not yet available",
                    uid
                )),
            }?;
            let setup = lwe::Setup::try_from(attributes).map_err(CError::msg)?;
            Ok((setup, lwe_msk))
        }
        _other => Err(anyhow::anyhow!(
            "The objet at uid: {} is not an MCFE LWE Functional Key",
            uid
        )
        .coded(StatusCode::BAD_REQUEST)),
    }
}

pub fn create_lwe_functional_key(
    master_secret_key_uid: &str,
    vectors: &[Vec<BigUint>],
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    let cr = lwe_functional_key_create_request(&FunctionalKeyCreateRequest {
        master_secret_key_uid: master_secret_key_uid.to_owned(),
        vectors: vectors.to_vec(),
    })
    .map_err(CError::msg)?;
    kms_client.create(&cr).map(|resp| resp.unique_identifier)
}

pub fn import_lwe_functional_key(
    setup: &lwe::Setup,
    key: &lwe::FunctionalKey,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    let n0_m0 = parameters.n0 + parameters.m0;
    check_argument!(
        n0_m0 == key.0.len(),
        "The functional key: contains: {} coefficients; {} expected",
        key.0.len(),
        n0_m0
    );

    let sk = secret_data_from_lwe_functional_key(setup, key)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

pub fn functional_key_share(
    secret_key_uid: &str,
    fks_secret_key_uid: &str,
    vectors: &[Vec<BigUint>],
    client: usize,
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<lwe::FunctionalKeyShare> {
    //TODO implement this inside the KMS as part of the encrypt operation
    let (sk_setup, secret_key) = get_lwe_key(secret_key_uid, LweSecretKeyType::Secret, kms_client)?;
    let (fks_sk_setup, fks_secret_key) =
        get_lwe_key(fks_secret_key_uid, LweSecretKeyType::FksSecret, kms_client)?;
    check_argument!(
        sk_setup == fks_sk_setup,
        "The secret key and the FKS secret do not have compatible parameters",
    );

    let parameters = lwe::Parameters::instantiate(&sk_setup).map_err(CError::msg)?;
    lwe::common::encrypted_functional_key_share(
        &parameters,
        &secret_key,
        &fks_secret_key,
        vectors,
        client,
    )
    .map_err(CError::msg)
}

pub fn recover_lwe_functional_key(
    setup: &lwe::Setup,
    functional_key_shares: &[lwe::FunctionalKeyShare],
    vectors: &[Vec<BigUint>],
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<String> {
    //TODO implement all this inside the KMS as part of the decrypt operation
    let parameters = lwe::Parameters::instantiate(setup).map_err(CError::msg)?;
    let fk = lwe::common::recover_functional_key(&parameters, functional_key_shares, vectors)
        .map_err(CError::msg)?;
    let sk = secret_data_from_lwe_functional_key(setup, &fk)?;
    let request = kmip_operations::Import {
        unique_identifier: "".to_string(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: attributes_from_key_block(ObjectType::SymmetricKey, sk.key_block()?)?,
        object: sk,
    };
    Ok(kms_client.import(request)?.unique_identifier)
}

// -----------------------
// LWE encrypt / decrypt
// -----------------------

pub fn encrypt(
    key_uid: &str,
    labeled_messages: &[(Vec<u8>, Vec<BigUint>)],
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<Vec<Vec<BigUint>>> {
    let request = kmip_operations::Encrypt {
        unique_identifier: Some(key_uid.to_string()),
        cryptographic_parameters: None,
        data: Some(serde_json::to_vec(&McfeEncryptionRequest(
            labeled_messages.to_owned(),
        ))?),
        iv_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    };
    let response = kms_client.encrypt(&request)?;
    Ok(if let Some(cts) = &response.data {
        serde_json::from_slice(cts)?
    } else {
        vec![]
    })
}

pub fn decrypt(
    functional_key_uid: &str,
    // vectors of client cipher texts and their corresponding label
    labeled_cipher_texts: &[(Vec<u8>, Vec<Vec<BigUint>>)],
    // n clients x m vector length
    vectors: &[Vec<BigUint>],
    kms_client: &dyn cosmian_kms_client::Client,
) -> CResult<Vec<BigUint>> {
    let request = kmip_operations::Decrypt {
        unique_identifier: Some(functional_key_uid.to_string()),
        cryptographic_parameters: None,
        data: Some(serde_json::to_vec(&McfeDecryptionRequest {
            labeled_cipher_texts: labeled_cipher_texts.to_vec(),
            vectors: vectors.to_vec(),
        })?),
        iv_counter_nonce: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        authenticated_encryption_tag: None,
    };
    let response = kms_client.decrypt(&request)?;
    Ok(if let Some(cts) = &response.data {
        serde_json::from_slice(cts)?
    } else {
        vec![]
    })
}

// -----------------------
// Create LWE FKS Secret keys
// TODO This will go ibn favor fo an MPC scheme
// -----------------------

pub fn fks_secret_keys(setup: &lwe::Setup) -> CResult<Vec<lwe::SecretKey>> {
    lwe::fks_secret_keys(
        &lwe::Parameters::instantiate(setup)
            .map_err(CError::msg)?
            .fks_parameters()
            .map_err(CError::msg)?,
    )
    .map_err(CError::msg)
}

/// Utility to check that an LWE Secret Key matches the given parameters
fn check_secret_key(
    client_number: usize,
    parameters: &lwe::Parameters,
    sk: &lwe::SecretKey,
) -> CResult<()> {
    let (m, n0_m0) = (parameters.message_length, parameters.n0 + parameters.m0);
    check_argument!(
        m == sk.0.len(),
        "There should be {} secret keys for client number: {}; {} found",
        m,
        client_number,
        sk.0.len()
    );

    for (mi, sk_mi) in sk.0.iter().enumerate() {
        check_argument!(
            n0_m0 == sk_mi.len(),
            "Client: {}, the secret key: {} contains: {} coefficients; {} expected",
            client_number,
            mi,
            sk_mi.len(),
            n0_m0
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use cosmian_crypto_base::cs_prng::Uniform;
    use cosmian_kms::kmip_server::KMSServer;
    use cosmian_mcfe::lwe::{Parameters, Setup};
    use num_bigint::BigUint;
    use rand::Rng;
    use tempfile::tempdir;

    use super::*;

    fn test_encryption_decryption(setup: &Setup) -> anyhow::Result<()> {
        let params = &Parameters::instantiate(setup)?;
        println!("Parameters: {}", params);
        // generate test data
        let n = params.clients;
        let m = params.message_length;
        let mut label = [0_u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for _c in 0..n {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&params.message_bound));
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut expected = BigUint::from(0_u32);
        for mi in 0..m {
            for i in 0..n {
                expected += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // KMS client
        let dir = tempdir()?;
        println!("Path: {:?}", dir);
        let kms_server = Arc::new(KMSServer::instantiate(dir.path())?);
        let client = cosmian_kms::LocalClient::new(kms_server);
        // master key generation
        let msk_uid = create_lwe_master_secret_key(setup, &client)?;
        let (rec_setup, rec_msk) = get_lwe_master_secret_key(&msk_uid, &client)?;
        assert_eq!(setup, &rec_setup);
        assert_eq!(rec_msk.len(), n);
        // Import master key
        let imported_msk_uid = import_lwe_master_secret_key(setup, &rec_msk, &client)?;
        let (rec_imported_setup, rec_imported_msk) =
            get_lwe_master_secret_key(&imported_msk_uid, &client)?;
        assert_eq!(setup, &rec_imported_setup);
        assert_eq!(rec_msk.len(), rec_imported_msk.len());
        assert_eq!(rec_msk[0].0.len(), rec_imported_msk[0].0.len());
        // Import each key separately
        let mut client_sk_uid_s: Vec<String> = Vec::with_capacity(params.clients);
        for sk_i in &rec_msk {
            client_sk_uid_s.push(import_lwe_secret_key(setup, sk_i, &client)?);
        }
        // Create LWE Functional Key
        let fk_uid = create_lwe_functional_key(&msk_uid, &vectors, &client)?;
        let (rec_setup, rec_fk) = get_lwe_functional_key(&fk_uid, &client)?;
        assert_eq!(setup, &rec_setup);
        assert_eq!(rec_fk.0.len(), params.n0 + params.m0);
        // Import master key
        let imported_fk_uid = import_lwe_functional_key(setup, &rec_fk, &client)?;
        let (rec_imported_setup, rec_imported_fk) =
            get_lwe_functional_key(&imported_fk_uid, &client)?;
        assert_eq!(setup, &rec_imported_setup);
        assert_eq!(rec_fk.0.len(), rec_imported_fk.0.len());
        //encryption
        let mut clients_cts: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for i in 0..params.clients {
            let labeled_messages: Vec<(Vec<u8>, Vec<BigUint>)> =
                vec![(b"0".to_vec(), messages[i].clone())];
            let cts = encrypt(&client_sk_uid_s[i], &labeled_messages, &client)?[0].clone();
            clients_cts.push(cts);
        }
        // decryption
        let labeled_cts = vec![(b"0".to_vec(), clients_cts)];
        let result = decrypt(&fk_uid, labeled_cts.as_slice(), &vectors, &client)?[0].clone();
        assert_eq!(&expected, &result);
        println!("  ==> OK");
        Ok(())
    }

    #[test]
    fn test_encryption_decryptions() -> anyhow::Result<()> {
        test_encryption_decryption(&Setup {
            clients: 3,
            message_length: 31,
            message_bound: BigUint::from(u32::max_value()),
            vectors_bound: BigUint::from(u32::max_value()),
            n0: 1024,
        })?;

        test_encryption_decryption(&Setup {
            clients: 5,
            message_length: 31,
            message_bound: BigUint::from(2_u32),
            vectors_bound: BigUint::from(u32::max_value()),
            n0: 1024,
        })?;
        Ok(())
    }
}
