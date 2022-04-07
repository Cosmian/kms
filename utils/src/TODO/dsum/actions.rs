// use crate::prelude::*;
// use actix_web::http::StatusCode;
// use cosmian_kms::{kmip_client, kmip_operations, kmip_types};
// use kmip_operations::OperationFailed;
// use kmip_types::Object;
// use std::convert::TryFrom;
// use std::convert::TryInto;

// // Get a Master Secret Key
// pub fn get_lwe_master_secret_key(
//     uid: &str,
//     kms_client: &dyn kmip_client::Client,
// ) -> CResult<(lwe::Setup, lwe::MasterSecretKey)> {
//     let gr = kms_client
//         .get(&kmip_operations::GetRequest::from(uid))
//         .map_err(of_to_c_error)?;
//     let object =
// Object::try_from(gr.object.as_slice()).map_err(of_to_c_error)?;
//     match object {
//         Object::SecretKey(sk) => {
//             if sk.key_block.key_format_type !=
// kmip_types::KeyFormatType::McfeMasterSecretKey {                 return
// Err(CError::from(format!(                     "The key at uid: {} is not an
// MCFE Lwe Master Secret Key",                     uid
//                 )));
//             }
//             let lwe_msk =
// lwe::MasterSecretKey::try_from(&sk).map_err(CError::from)?;             let
// attributes = match sk.key_block.key_value {
// kmip_types::KeyValue::PlainText(pt) => pt.attributes.ok_or_else(|| {
//                     CError::from(format!("The key at uid: {} is missing its
// attributes", uid))                 }),
//                 kmip_types::KeyValue::Wrapped(_) => Err(CError::from(format!(
//                     "The key at uid: {} is wrapped and this not yet
// available",                     uid
//                 ))),
//             }?;
//             let setup = lwe::Setup::try_from(&attributes)?;
//             Ok((setup, lwe_msk))
//         }
//         _other => Err(CError::new_coded(
//             format!(
//                 "The objet at uid: {} is not an MCFE LWE Master Secret Key",
//                 uid
//             ),
//             StatusCode::BAD_REQUEST,
//         )),
//     }
// }
