mod find;
#[allow(dead_code)]
//TODO: the quick cert functionality needs to be completely revisited as it is not part of KMIP and converted to openssl
mod quick_cert;
mod tags;

pub(crate) use find::{
    retrieve_certificate_for_private_key, retrieve_matching_private_key_and_certificate,
};
pub(crate) use tags::{
    add_attributes_to_certificate_tags, add_certificate_system_tags,
    add_certificate_tags_to_attributes,
};
