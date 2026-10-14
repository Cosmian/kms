use super::{KaclsKeyMetadata, KeyPairInfo, PrivateKeyMetadata};

fn build_key_pair_info() -> KeyPairInfo {
    KeyPairInfo {
        pkcs7: "PKCS7DATA".to_owned(),
        privateKeyMetadata: vec![PrivateKeyMetadata {
            kaclsKeyMetadata: KaclsKeyMetadata {
                kaclsUri: "https://kacls.example.com/v1".to_owned(),
                kaclsData: "wrapped-data".to_owned(),
            },
        }],
    }
}

#[test]
fn characterization_key_pair_info_serializes_camel_case() {
    let json = serde_json::to_string(&build_key_pair_info()).unwrap();
    assert_eq!(
        json,
        r#"{"pkcs7":"PKCS7DATA","privateKeyMetadata":[{"kaclsKeyMetadata":{"kaclsUri":"https://kacls.example.com/v1","kaclsData":"wrapped-data"}}]}"#
    );
}

#[test]
fn characterization_key_pair_info_round_trips() {
    let json = serde_json::to_string(&build_key_pair_info()).unwrap();
    let parsed: KeyPairInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
}
