use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Certificate, Object, ObjectType},
    kmip_types::CertificateType,
};

use crate::stores::DBObject;

#[test]
fn serde_json_db_object() {
    let cert = Object::Certificate(Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: vec![1, 2, 3, 4],
    });
    let json = serde_json::to_string(&cert).unwrap();
    // println!("CERT JSON: {}", json);
    let cert_: Object = serde_json::from_str(json.as_str()).unwrap();
    // println!("CERT REC: {:?}", cert_);
    assert_eq!(cert, cert_);

    let db_object = DBObject {
        object_type: ObjectType::Certificate,
        object: cert,
    };
    let json = serde_json::to_string(&db_object).unwrap();
    // println!("DBOject {}", json);

    let _object: Object = serde_json::from_str(&json).unwrap();
    // println!("{:?}", object);

    // let value: Value = serde_json::from_str(json.as_str()).unwrap();
    // // {"object_type":"Certificate","object":{"CertificateType":"X509","CertificateValue":[1,2,3,4]}}
    // let object_type = value["object_type"].as_str().unwrap();
    // let content = &value["object"].as_object().unwrap();
    //
    // let new_object = json!({object_type: content});
    // println!("{}", new_object.to_string());
    // let object: Object = serde_json::from_value(new_object).unwrap();
    // println!("{:?}", object);
    // println!("{:?}", serde_json::to_string(&object).unwrap());
}
