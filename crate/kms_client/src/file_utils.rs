use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializer};
use cosmian_kms_client_utils::export_utils::tag_from_object;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    cosmian_kmip::{
        kmip_2_1::kmip_objects::Object,
        ttlv::{TTLV, from_ttlv, to_ttlv},
    },
    error::{KmsClientError, result::KmsClientResultHelper},
};

/// Read all bytes from a file
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_bytes_from_file(file: &impl AsRef<Path>) -> Result<Vec<u8>, KmsClientError> {
    let mut buffer = Vec::new();
    File::open(file)
        .with_context(|| format!("could not open the file {}", file.as_ref().display()))?
        .read_to_end(&mut buffer)
        .with_context(|| format!("could not read the file {}", file.as_ref().display()))?;

    Ok(buffer)
}

/// Read an object T from a JSON file
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_from_json_file<T>(file: &impl AsRef<Path>) -> Result<T, KmsClientError>
where
    T: DeserializeOwned,
{
    let buffer = read_bytes_from_file(file)?;
    serde_json::from_slice::<T>(&buffer)
        .with_context(|| "failed parsing the object from the json file")
}

/// Read an object from KMIP JSON TTLV bytes slice
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> Result<Object, KmsClientError> {
    // Read the object from the file
    let ttlv = serde_json::from_slice::<TTLV>(bytes)
        .with_context(|| "failed parsing the object from the bytes")?;
    // Deserialize the object
    let object: Object = from_ttlv(ttlv)?;
    Ok(object)
}

/// Read an  object from a KMIP JSON TTLV file
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_object_from_json_ttlv_file(object_file: &PathBuf) -> Result<Object, KmsClientError> {
    let bytes = read_bytes_from_file(object_file)?;
    read_object_from_json_ttlv_bytes(&bytes)
}

/// Write all bytes to a file
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_bytes_to_file(bytes: &[u8], file: &impl AsRef<Path>) -> Result<(), KmsClientError> {
    fs::write(file, bytes).with_context(|| {
        format!(
            "failed writing {} bytes to {}",
            bytes.len(),
            file.as_ref().display()
        )
    })
}

/// Write a JSON object to a file
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_json_object_to_file<T>(
    json_object: &T,
    file: &impl AsRef<Path>,
) -> Result<(), KmsClientError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec::<T>(json_object)
        .with_context(|| "failed writing the object from the json object")?;
    write_bytes_to_file(&bytes, file)
}

/// Writes a KMIP Object to a JSON TTLV in a file.
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_kmip_object_to_file(
    kmip_object: &Object,
    object_file: &impl AsRef<Path>,
) -> Result<(), KmsClientError> {
    // serialize the returned object to JSON TTLV
    let mut ttlv = to_ttlv(kmip_object)?;
    // set the top tag to the object type
    ttlv.tag = tag_from_object(kmip_object);
    // write the JSON TTLV to a file
    write_json_object_to_file(&ttlv, object_file)
}

/// Write the decrypted data to a file
///
/// If no `output_file` is provided, then
/// it reuses the `input_file` name with the extension `plain`.
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_single_decrypted_data(
    plaintext: &[u8],
    input_file: &Path,
    output_file: Option<&PathBuf>,
) -> Result<(), KmsClientError> {
    let output_file = output_file.map_or_else(
        || input_file.with_extension("plain"),
        std::clone::Clone::clone,
    );

    write_bytes_to_file(plaintext, &output_file)
        .with_context(|| "failed to write the decrypted file")?;

    tracing::info!("The decrypted file is available at {output_file:?}");
    Ok(())
}

/// Write the encrypted data to a file
///
/// If no `output_file` is provided, then
/// it reuses the `input_file` name with the extension `enc`.
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_single_encrypted_data(
    encrypted_data: &[u8],
    input_file: &Path,
    output_file: Option<&PathBuf>,
) -> Result<(), KmsClientError> {
    // Write the encrypted file
    let output_file = output_file.map_or_else(
        || input_file.with_extension("enc"),
        std::clone::Clone::clone,
    );

    write_bytes_to_file(encrypted_data, &output_file)
        .with_context(|| "failed to write the encrypted file")?;

    tracing::info!("The encrypted file is available at {output_file:?}");
    Ok(())
}

/// Read all bytes from multiple files and serialize them
/// into a unique vector using LEB128 serialization (bulk mode)
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_bytes_from_files_to_bulk(input_files: &[PathBuf]) -> Result<Vec<u8>, KmsClientError> {
    let mut ser = Serializer::new();

    // number of files to decrypt
    let nb_input_files = u64::try_from(input_files.len()).map_err(|e| {
        KmsClientError::Conversion(format!(
            "number of input files is too big for architecture: {} bytes. Error: {e}",
            input_files.len()
        ))
    })?;
    ser.write_leb128_u64(nb_input_files)?;

    input_files.iter().try_for_each(|input_file| {
        let content = read_bytes_from_file(input_file)?;
        ser.write_vec(&content)?;
        Ok::<_, KmsClientError>(())
    })?;

    Ok(ser.finalize().to_vec())
}

/// Write bulk decrypted data
///
/// Bulk data is compound of multiple chunks of data.
/// Sizes are written using LEB-128 serialization.
///
/// Each chunk of plaintext data is written to its own file.
/// # Errors
/// If decryption fails
#[expect(clippy::indexing_slicing)]
pub fn write_bulk_decrypted_data(
    plaintext: &[u8],
    input_files: &[PathBuf],
    output_file: Option<&PathBuf>,
) -> Result<(), KmsClientError> {
    let mut de = Deserializer::new(plaintext);

    // number of decrypted chunks
    let nb_chunks = {
        let len = de.read_leb128_u64()?;
        usize::try_from(len).map_err(|e| {
            KmsClientError::Conversion(format!(
                "size of vector is too big for architecture: {len} bytes. Error: {e}",
            ))
        })?
    };

    (0..nb_chunks).try_for_each(|idx| {
        // get chunk of data from slice
        let chunk_data = de.read_vec_as_ref()?;

        // Write plaintext data to its own file
        // Reuse input file names if there are multiple inputs (and ignore `output_file`)
        let input_file = &input_files[idx];
        let output_file = match output_file {
            Some(output_file) if nb_chunks > 1 => {
                let file_name = input_file.file_name().ok_or_else(|| {
                    KmsClientError::Conversion(format!(
                        "cannot get file name from input file {}",
                        input_file.display()
                    ))
                })?;
                output_file.join(PathBuf::from(file_name).with_extension("plain"))
            }
            _ => output_file.map_or_else(
                || input_file.with_extension("plain"),
                std::clone::Clone::clone,
            ),
        };

        write_bytes_to_file(chunk_data, &output_file)?;

        tracing::info!("The decrypted file is available at {output_file:?}");
        Ok(())
    })
}

/// Write bulk encrypted data
///
/// Bulk data is compound of multiple chunks of data.
/// Sizes are written using LEB-128 serialization.
///
/// Each chunk of data:
/// - is compound of encrypted header + encrypted data
/// - is written to its own file.
/// # Errors:
/// If encryption fails
/// # Errors
/// If encryption fails
#[expect(clippy::indexing_slicing)]
pub fn write_bulk_encrypted_data(
    plaintext: &[u8],
    input_files: &[PathBuf],
    output_file: Option<&PathBuf>,
) -> Result<(), KmsClientError> {
    let mut de = Deserializer::new(plaintext);

    // number of encrypted chunks
    let nb_chunks = {
        let len = de.read_leb128_u64()?;
        usize::try_from(len).map_err(|e| {
            KmsClientError::Conversion(format!(
                "size of vector is too big for architecture: {len} bytes. Error: {e}",
            ))
        })?
    };

    (0..nb_chunks).try_for_each(|idx| {
        // get chunk of data from slice
        let chunk_data = de.read_vec_as_ref()?;

        // Write encrypted data to its own file
        // Reuse input file names if there are multiple inputs (and ignore `output_file`)
        let input_file = &input_files[idx];
        let output_file = match output_file {
            Some(output_file) if nb_chunks > 1 => {
                let file_name = input_file.file_name().ok_or_else(|| {
                    KmsClientError::Conversion(format!(
                        "cannot get file name from input file {}",
                        input_file.display()
                    ))
                })?;
                output_file.join(PathBuf::from(file_name).with_extension("enc"))
            }
            _ => output_file.map_or_else(
                || input_file.with_extension("enc"),
                std::clone::Clone::clone,
            ),
        };

        write_bytes_to_file(chunk_data, &output_file)?;

        tracing::info!("The encrypted file is available at {output_file:?}");
        Ok(())
    })
}
