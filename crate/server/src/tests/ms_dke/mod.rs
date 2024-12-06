#![allow(clippy::unwrap_used, clippy::print_stdout)]

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Decrypt, DecryptResponse, Import, ImportResponse},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm,
        KeyFormatType, PaddingMethod, UniqueIdentifier,
    },
};

use crate::{kms_error, result::KResult, routes::ms_dke::EncryptedData, tests::test_utils};

const RSA_PRIVATE_KEY: &str = r"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNzNM2hQNhfdUO
7hTM9F/a4ZNfCBnIpTP6VRvHNLcA7T8Zt+2+ozC7zKneXGXAfs70zLfa00wAlcm0
FJ/4OJoPfEgDodN05rh0e8hmUjGs15HJAu5QS7b6p1zn/HUUmYSS4bffG6cV54BR
TcI1I7lf4hnedLet04gvrDABJUkoE+Az0Af3nGqbFdA04WmZuuK/9zlUCp3siHzc
fwoHOjCxhE1iJaogm8VU/bbinZQ02qmvRZf5A+SChBgfmEoZFHxuPcFViHOUQT7j
8FAunYQJ9JgJ7WRFiqV9KkFEeusqFn5VwSxiD/3NsAo+Ytzh9ExHropobkA2l7s6
x5UUsfI1AgMBAAECggEAFB4BvhufV+q7+icFTPGDkuBLYeFalRh4+BQwgXHFX8yI
1ft973yj+pTF6b3Wkrl634iWseUlxHR7vgBqFJNlKfrCFb/U6eIcu6vfCcMx+HlJ
3ch8amhfgI6Tc/chXieMgzEiPrUj3ovuLLq5KYRUtZl0fZa2A2N+D/NgCR2S1CxN
oy0Yvj7eMlRlGpOcoc/6dIJjJoS3PcxRMxAquIJsY8rBjkZ8F8AtaDS+F1nbTH6a
D3HazA4eIWmb3mxiRkRV3P1X6JVCplyr7yGmWnUN5T+mwygH89K2mP1K9Zxr9MWw
jUt84PtsR1WX+V8gGZWxHDqNCp8WiHH0qnqrzDqiYQKBgQDAy+PmePj36DmagxJO
p16usED7oYRvzab/XvYI/hQKQqiyey4G8JnEkKdtY2RV2sBLJmKiSdE+YsPRqhl3
mWBDtEg25UipEZAiH0BDu0Jg92iUP4FSPWc7h/Rt+W3O7Gt+UetpKRAnWWSyxgJ9
GG/mt+N58r8B79yOp4rynzxWIQKBgQC8SSdye2g31VmukxGZk1iDbVnVg1XYQcOj
E7MteFNUHLUeDO2XYgdhp1/hmLiaTCVvrhDp1WqwNthaOidV+ysSzABu316yq4Pm
qdcVsSoak69Rw50AXbxNju0Yz6YuYxUAjWQ5Jk8+gNplwRN3ha4lXpKUJBld92vM
el1ikCexlQKBgFlu+1QRL+TIC9iaDqb/ytMcHbjcbvPyIRJ7OYRoYGF2FI1eyLYd
bCcbtx7uKUAOTn9N2hlQRsk6xX1/+3pYYqhle85DRBZxeDvr5ULGHf+fJRsH7nR4
2WdrJL7TItYHI8IgPCS3ELBALo8jfUoMSPRsvw/1xBcg7l4aaEEuDq4hAoGBAIyF
EDKplVMuIDtguV7jj8iugMAPv66hDjAUEMJbrdz1e9qMjXlQiO/BqZZFk2hccggS
Yb8SLwiKNhfIlPjfdfsWUzBr9lHkHZG1qbcfvKuPEuYz1mWij1lW1O6ScpTmD5OU
8nqQc83S/qu4WB34n8p19XEoK+JsOICnxjA8I9OtAoGAVziHvUjC84B6BXVuC5B3
KLNVGWKs8oqvZIgRXhp3Yu4Kw41PKyQYPyQ91TAUbSvahkrNOwALmabx9OovNGtD
3IvcjbcH8hlJ1MmqxObwe4Hun4A3/ekv0G08kIRpkBgVeVhY3MJ2uKo+3LIk5AMf
jRuCab6FPsJq5BTA5QYDjR8=
-----END PRIVATE KEY-----
";

const ENCRYPTED_DATA: &str = r#"{
    "alg":"RSA-OAEP-256",
    "value":"SowuwT1RuQalev5OCYFhpGaziwOqiTgzQcRfcITsukcBOsX61SejEF91cnx8vQv/gjmovXW4qEV7PpNBKj2GMszHWmFkt877raP02yxch6w0sPEBMaNdfbLIScpsjaPAOmu/i3MAY3dPaAl4duGE3FJCb1O8G98QamB5eQXpJaKcoUGUCeE4hy4qi5k15rQWMU6EmTZ8qL37ugDGo1gRuSsYZmCriPH+sUdiOIXEBJ/UrRIeR+ENPgjBVRSw46sbfdCIee37iROdBRxffHe2p+Ntx1TGMSLhkOc+DU0p+0+cDEicmVXorUfNZCQc7Rof2pIjpUI4Qi3wBCexTnZXgw=="
}"#;

#[ignore]
#[tokio::test]
async fn decrypt_data_test() -> KResult<()> {
    cosmian_logger::log_init(None);

    let app = test_utils::test_app(None).await;

    let pem = pem::parse(RSA_PRIVATE_KEY.as_bytes())
        .map_err(|e| kms_error!(format!("cannot parse RSA private key: {}", e)))?;

    let import_key = Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: Attributes::default(),
        object: Object::PublicKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(pem.contents().to_vec().into()),
                    attributes: None,
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: None,
                key_wrapping_data: None,
            },
        },
    };
    let import_response: ImportResponse = test_utils::post(&app, &import_key).await?;
    let key_id = import_response.unique_identifier;

    // encrypted data
    let encrypted_data: EncryptedData = serde_json::from_str(ENCRYPTED_DATA)?;
    let ciphertext = STANDARD.decode(encrypted_data.value.as_bytes())?;

    let decrypt_request = Decrypt {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..CryptographicParameters::default()
        }),
        data: Some(ciphertext),
        ..Decrypt::default()
    };
    let decrypt_response: DecryptResponse = test_utils::post(&app, &decrypt_request).await?;
    println!("plaintext: {:?}", decrypt_response.data);
    println!(
        "plaintext len: {:?}",
        decrypt_response.data.as_ref().unwrap().len()
    );

    Ok(())
}
