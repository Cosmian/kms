use crate::kmip::{
    kmip_operations::Get,
    kmip_types::{KeyFormatType, UniqueIdentifier},
};

#[must_use]
pub fn get_rsa_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_rsa_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_ec_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_ec_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        ..Get::default()
    }
}
