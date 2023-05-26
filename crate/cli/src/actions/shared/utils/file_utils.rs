use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::KeyFormatType,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Read a JSON policy specification from a file
pub fn read_bytes_from_file(file: &impl AsRef<Path>) -> Result<Vec<u8>, CliError> {
    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("could not open the file {}", file.as_ref().display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("could not read the file {}", file.as_ref().display()))?;

    Ok(buffer)
}

/// Read an object T from a JSON file
pub fn read_from_json_file<T>(file: &impl AsRef<Path>) -> Result<T, CliError>
where
    T: DeserializeOwned,
{
    let buffer = read_bytes_from_file(file)?;
    serde_json::from_slice::<T>(&buffer)
        .with_context(|| "failed parsing the object from the json file")
}

pub(crate) fn determine_key_object_type(object: &Object) -> Result<ObjectType, CliError> {
    let key_block = object.key_block().context("invalid key block")?;
    Ok(match key_block.key_format_type {
        KeyFormatType::CoverCryptSecretKey => ObjectType::PrivateKey,
        KeyFormatType::CoverCryptPublicKey => ObjectType::PublicKey,
        KeyFormatType::TransparentSymmetricKey => ObjectType::SymmetricKey,
        KeyFormatType::TransparentECPrivateKey => ObjectType::PrivateKey,
        KeyFormatType::TransparentECPublicKey => ObjectType::PublicKey,
        KeyFormatType::TransparentDHPrivateKey => ObjectType::PrivateKey,
        KeyFormatType::TransparentDHPublicKey => ObjectType::PublicKey,
        x => cli_bail!("not a supported key format: {}", x),
    })
}

// Read an object from a KMIP jSON TTLV file
pub fn read_object_from_file<F>(
    object_file: &PathBuf,
    post_fix_helper: F,
) -> Result<Object, CliError>
where
    F: Fn(&Object) -> Result<ObjectType, CliError>,
{
    // Read the object from the file
    let ttlv: TTLV = read_from_json_file(object_file)?;
    // Deserialize the object
    let object: Object = from_ttlv(&ttlv)?;
    // Post fix the object type
    let object_type = post_fix_helper(&object)?;
    let object = Object::post_fix(object_type, object);

    Ok(object)
}

// Read a key from a KMIP jSON TTLV file
pub fn read_key_from_file(object_file: &PathBuf) -> Result<Object, CliError> {
    read_object_from_file(object_file, determine_key_object_type)
}

/// Read all bytes from a file
pub fn write_bytes_to_file(bytes: &[u8], file: &impl AsRef<Path>) -> Result<(), CliError> {
    fs::write(file, bytes).with_context(|| {
        format!(
            "failed writing {} bytes to {:?}",
            bytes.len(),
            file.as_ref()
        )
    })
}

/// Write an object T from a JSON file
pub fn write_to_json_file<T>(json_object: &T, file: &impl AsRef<Path>) -> Result<(), CliError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec::<T>(json_object)
        .with_context(|| "failed parsing the object from the json file")?;
    write_bytes_to_file(&bytes, file)
}

// Writes a KMIP Object to a JSON TTLV in a file.
pub fn write_kmip_object_to_file(
    kmip_object: &Object,
    object_file: &impl AsRef<Path>,
) -> Result<(), CliError> {
    // serialize the returned object to JSON TTLV
    let mut ttlv = to_ttlv(kmip_object)?;
    // set the top tag to the object type
    ttlv.tag = tag_from_object(kmip_object);
    // write the JSON TTLV to a file
    write_to_json_file(&ttlv, object_file)
}

#[must_use]
/// Return the KMIP tag for a given object
/// This is required to match the Java library behavior which expects
/// the first tag to describe the type of object and not simply equal 'Object'
// TODO: check what is specified by the KMIP norm if any
fn tag_from_object(object: &Object) -> String {
    match &object {
        Object::PublicKey { .. } => "PublicKey",
        Object::SecretData { .. } => "SecretData",
        Object::PGPKey { .. } => "PGPKey",
        Object::SymmetricKey { .. } => "SymmetricKey",
        Object::SplitKey { .. } => "SplitKey",
        Object::Certificate { .. } => "Certificate",
        Object::CertificateRequest { .. } => "CertificateRequest",
        Object::OpaqueObject { .. } => "OpaqueObject",
        Object::PrivateKey { .. } => "PrivateKey",
    }
    .to_string()
}
