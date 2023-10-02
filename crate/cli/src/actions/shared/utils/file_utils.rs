use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use cloudproof::reexport::crypto_core::bytes_ser_de::{Deserializer, Serializer};
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

/// Read all bytes from a file
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
    match object.object_type() {
        ObjectType::Certificate => Ok(ObjectType::Certificate),
        _ => {
            let key_block = object.key_block().context("invalid key block")?;
            Ok(match key_block.key_format_type {
                KeyFormatType::CoverCryptSecretKey => ObjectType::PrivateKey,
                KeyFormatType::CoverCryptPublicKey => ObjectType::PublicKey,
                KeyFormatType::TransparentSymmetricKey => ObjectType::SymmetricKey,
                KeyFormatType::TransparentECPrivateKey => ObjectType::PrivateKey,
                KeyFormatType::TransparentECPublicKey => ObjectType::PublicKey,
                KeyFormatType::TransparentDHPrivateKey => ObjectType::PrivateKey,
                KeyFormatType::TransparentDHPublicKey => ObjectType::PublicKey,
                KeyFormatType::TransparentRSAPrivateKey => ObjectType::PrivateKey,
                KeyFormatType::TransparentRSAPublicKey => ObjectType::PublicKey,
                x => cli_bail!("not a supported key format: {x}"),
            })
        }
    }
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

/// Write all bytes to a file
pub fn write_bytes_to_file(bytes: &[u8], file: &impl AsRef<Path>) -> Result<(), CliError> {
    fs::write(file, bytes).with_context(|| {
        format!(
            "failed writing {} bytes to {:?}",
            bytes.len(),
            file.as_ref()
        )
    })
}

/// Write a JSON object to a file
pub fn write_json_object_to_file<T>(
    json_object: &T,
    file: &impl AsRef<Path>,
) -> Result<(), CliError>
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
    write_json_object_to_file(&ttlv, object_file)
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

/// Write the decrypted data to a file
///
/// If no `output_file` is provided, then
/// it reuses the `input_file` name with the extension `plain`.
pub fn write_single_decrypted_data(
    plaintext: &[u8],
    input_file: &Path,
    output_file: Option<&PathBuf>,
) -> Result<(), CliError> {
    let output_file = output_file.map_or_else(
        || input_file.with_extension("plain"),
        std::clone::Clone::clone,
    );

    write_bytes_to_file(plaintext, &output_file)
        .with_context(|| "failed to write the decrypted file")?;

    println!("The decrypted file is available at {output_file:?}");
    Ok(())
}

/// Write the encrypted data to a file
///
/// If no `output_file` is provided, then
/// it reuses the `input_file` name with the extension `enc`.
pub fn write_single_encrypted_data(
    encrypted_data: &[u8],
    input_file: &Path,
    output_file: Option<&PathBuf>,
) -> Result<(), CliError> {
    // Write the encrypted file
    let output_file = output_file.map_or_else(
        || input_file.with_extension("enc"),
        std::clone::Clone::clone,
    );

    write_bytes_to_file(encrypted_data, &output_file)
        .with_context(|| "failed to write the encrypted file")?;

    println!("The encrypted file is available at {output_file:?}");
    Ok(())
}

/// Read all bytes from multiple files and serialize them
/// into a unique vector using LEB128 serialization (bulk mode)
pub fn read_bytes_from_files_to_bulk(input_files: &[PathBuf]) -> Result<Vec<u8>, CliError> {
    let mut ser = Serializer::new();

    // number of files to decrypt
    let nb_input_files = u64::try_from(input_files.len()).map_err(|_| {
        CliError::Conversion(format!(
            "number of input files is too big for architecture: {} bytes",
            input_files.len()
        ))
    })?;
    ser.write_leb128_u64(nb_input_files)?;

    input_files.iter().try_for_each(|input_file| {
        let content = read_bytes_from_file(input_file)?;
        ser.write_vec(&content)?;
        Ok::<_, CliError>(())
    })?;

    Ok(ser.finalize().to_vec())
}

/// Write each decrypted data to its own file.
pub fn write_bulk_decrypted_data(
    plaintext: &[u8],
    input_files: &[PathBuf],
    output_file: Option<&PathBuf>,
) -> Result<(), CliError> {
    let mut de = Deserializer::new(plaintext);

    // number of decrypted chunks
    let nb_chunks = {
        let len = de.read_leb128_u64()?;
        usize::try_from(len).map_err(|_| {
            CliError::Conversion(format!(
                "size of vector is too big for architecture: {len} bytes",
            ))
        })?
    };

    (0..nb_chunks).try_for_each(|idx| {
        // get chunk of data from slice
        let chunk_data = de.read_vec_as_ref()?;

        // Write the decrypted files
        // Reuse input file names if there are multiple inputs (and ignore `output_file`)
        let output_file = if nb_chunks == 1 {
            output_file.map_or_else(
                || input_files[idx].with_extension("plain"),
                std::clone::Clone::clone,
            )
        } else if let Some(output_file) = &output_file {
            let file_name = input_files[idx].file_name().ok_or_else(|| {
                CliError::Conversion(format!(
                    "cannot get file name from input file {:?}",
                    input_files[idx],
                ))
            })?;
            output_file.join(PathBuf::from(file_name).with_extension("plain"))
        } else {
            input_files[idx].with_extension("plain")
        };

        write_bytes_to_file(chunk_data, &output_file)?;

        println!("The decrypted file is available at {output_file:?}");
        Ok(())
    })
}
