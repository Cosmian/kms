//! Characterization tests pinning BASE behavior of `derive_session_key_from_url`.

use super::derive_session_key_from_url;

const INPUTS: [(&str, &str); 3] = [
    ("https://kms.example.com", "salt-seed"),
    ("http://localhost:9998", "another seed"),
    ("", "x"),
];

/// FIPS builds derive the key with PBKDF2.
#[cfg(not(feature = "non-fips"))]
const GOLDEN: [&str; 3] = [
    "80788cf852702e730812c9c7099b3ddf2ce2a89f5b778925d16a878ad18adc5489019e2d0d55a811d4d8baac17fd5ed28428b152ec1e5e06decb97c455ee43d7",
    "d0199379e84f9b075d467db05c105bc2ae29aa5deff7125a5ead632f09da1c263213d5797255fee02ba4e2415f75331efb84f3ae1dcca85046b43f57ab6f361a",
    "904a45d88bc08a7dfd8a60ee1736f441cb2d48d757f05619e1c1668ffa7f66d3108b01bfea801f278f31f7e8a888c5d546a234f4104f1f0b70612d58d9e199c9",
];

/// Non-FIPS builds derive the key with Argon2.
#[cfg(feature = "non-fips")]
const GOLDEN: [&str; 3] = [
    "63f57eb44bcf400861970fe398a083119d9fc2578f4e3f578316d44eea7c5725a393fe6139f1772f58bad78b6fa7fc460cbc29ecf45e9c117b9fb9665bd7a668",
    "e8a6adab7054d4aaa82a130dc53c82dedc44714c7a196e96234a024c55e3c4b37208ef6fb1080c16493c0b38ee699833f8f2c5e642da3b4a793b72e2f7a82359",
    "6b54c77f007beb08287fa5e80d48fc9d41d3fa76b8037d45e6bcf7f50c507262b1d0c00cace05c376876571f9ce84120933eaec16c024f717bef6d6aa7b69b1b",
];

#[test]
fn characterization_derive_session_key_from_url_golden() {
    let derived: Vec<String> = INPUTS
        .iter()
        .map(|(url, salt)| hex::encode(derive_session_key_from_url(url, salt).unwrap().master()))
        .collect();
    assert_eq!(derived, GOLDEN.to_vec());
}

#[test]
fn characterization_derive_session_key_from_url_is_deterministic() {
    let a = derive_session_key_from_url("https://kms.example.com", "salt-seed").unwrap();
    let b = derive_session_key_from_url("https://kms.example.com", "salt-seed").unwrap();
    let c = derive_session_key_from_url("https://kms.example.com", "salt-seee").unwrap();
    assert_eq!(a.master(), b.master());
    assert_ne!(a.master(), c.master());
    assert_eq!(a.master().len(), 64);
}
