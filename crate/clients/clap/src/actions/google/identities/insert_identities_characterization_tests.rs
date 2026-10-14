use super::IdentityInfo;

fn build_identity_info() -> IdentityInfo {
    IdentityInfo {
        primaryKeyPairId: "kp-1".to_owned(),
        emailAddress: "alice@example.com".to_owned(),
    }
}

#[test]
fn characterization_identity_info_serializes_camel_case() {
    let json = serde_json::to_string(&build_identity_info()).unwrap();
    assert_eq!(
        json,
        r#"{"primaryKeyPairId":"kp-1","emailAddress":"alice@example.com"}"#
    );
}

#[test]
fn characterization_identity_info_deserializes_camel_case() {
    let info: IdentityInfo =
        serde_json::from_str(r#"{"emailAddress":"b@x.y","primaryKeyPairId":"k2"}"#).unwrap();
    let json = serde_json::to_string(&info).unwrap();
    assert_eq!(json, r#"{"primaryKeyPairId":"k2","emailAddress":"b@x.y"}"#);
}
