use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializer};
use cosmian_kms_client_utils::export_utils::tag_from_object;
use cosmian_logger::info;
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
    serde_json::from_slice::<T>(&buffer).context("failed parsing the object from the json file")
}

/// Read an object from KMIP JSON TTLV bytes slice
/// # Errors
/// If the file cannot be opened or read, an error is returned.
pub fn read_object_from_json_ttlv_bytes(bytes: &[u8]) -> Result<Object, KmsClientError> {
    // Read the object from the file
    let ttlv = serde_json::from_slice::<TTLV>(bytes)
        .context("failed parsing the object from the bytes")?;
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
        .context("failed writing the object from the json object")?;
    write_bytes_to_file(&bytes, file)
}

/// Writes a KMIP Object to a JSON TTLV in a file.
/// # Errors
/// If the file cannot be opened or written, an error is returned.
pub fn write_kmip_object_to_file(
    kmip_object: &Object,
    object_file: &impl AsRef<Path>,
) -> Result<(), KmsClientError> {
    let mut ttlv = to_ttlv(kmip_object)?;
    ttlv.tag = tag_from_object(kmip_object).into();
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

    write_bytes_to_file(plaintext, &output_file).context("failed to write the decrypted file")?;

    info!("The decrypted file is available at {output_file:?}");
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
        .context("failed to write the encrypted file")?;

    info!("The encrypted file is available at {output_file:?}");
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
        let chunk_data = de.read_vec_as_ref()?;

        // Write plaintext data to its own file
        // Reuse input file names if there are multiple inputs (and ignore `output_file`)
        let input_file = input_files.get(idx).ok_or_else(|| {
            KmsClientError::Conversion(format!("missing input file for chunk {idx}"))
        })?;
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

        info!("The decrypted file is available at {output_file:?}");
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
        let chunk_data = de.read_vec_as_ref()?;

        // Write encrypted data to its own file
        // Reuse input file names if there are multiple inputs (and ignore `output_file`)
        let input_file = input_files.get(idx).ok_or_else(|| {
            KmsClientError::Conversion(format!("missing input file for chunk {idx}"))
        })?;
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

        info!("The encrypted file is available at {output_file:?}");
        Ok(())
    })
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests for the bulk read/write helpers of `file_utils`.

    use std::path::PathBuf;

    use cosmian_crypto_core::bytes_ser_de::Serializer;

    use super::{write_bulk_decrypted_data, write_bulk_encrypted_data};

    fn bulk(chunks: &[&[u8]]) -> Vec<u8> {
        let mut ser = Serializer::new();
        ser.write_leb128_u64(u64::try_from(chunks.len()).unwrap())
            .unwrap();
        for chunk in chunks {
            ser.write_vec(chunk).unwrap();
        }
        ser.finalize().to_vec()
    }

    /// A fresh, empty, uniquely named scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "kms_client_characterization_{name}_{}",
                std::process::id()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, file: &str) -> PathBuf {
            self.0.join(file)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_multiple_inputs_into_output_dir() {
        let scratch = Scratch::new("enc_multi_dir");
        let out_dir = scratch.path("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let inputs = [
            scratch.path("a.txt"),
            scratch.path("b.bin"),
            scratch.path("c"),
        ];
        let data = bulk(&[b"first", b"", b"third-chunk"]);
        write_bulk_encrypted_data(&data, &inputs, Some(&out_dir)).unwrap();
        assert_eq!(std::fs::read(out_dir.join("a.enc")).unwrap(), b"first");
        assert_eq!(std::fs::read(out_dir.join("b.enc")).unwrap(), b"");
        assert_eq!(
            std::fs::read(out_dir.join("c.enc")).unwrap(),
            b"third-chunk"
        );
        assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 3);
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_multiple_inputs_without_output() {
        let scratch = Scratch::new("enc_multi_none");
        let inputs = [scratch.path("a.txt"), scratch.path("b.bin")];
        let data = bulk(&[b"alpha", b"beta"]);
        write_bulk_encrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(std::fs::read(scratch.path("a.enc")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(scratch.path("b.enc")).unwrap(), b"beta");
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_single_chunk_uses_output_file_as_is() {
        let scratch = Scratch::new("enc_single_out");
        let inputs = [scratch.path("a.txt")];
        let output = scratch.path("explicit.out");
        let data = bulk(&[b"only"]);
        write_bulk_encrypted_data(&data, &inputs, Some(&output)).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"only");
        assert!(!scratch.path("a.enc").exists());
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_single_chunk_without_output() {
        let scratch = Scratch::new("enc_single_none");
        let inputs = [scratch.path("data.tar.gz")];
        let data = bulk(&[b"only"]);
        write_bulk_encrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(
            std::fs::read(scratch.path("data.tar.enc")).unwrap(),
            b"only"
        );
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_extra_inputs_are_ignored() {
        let scratch = Scratch::new("enc_extra");
        let inputs = [
            scratch.path("a.txt"),
            scratch.path("b.txt"),
            scratch.path("c.txt"),
        ];
        let data = bulk(&[b"one", b"two"]);
        write_bulk_encrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(std::fs::read(scratch.path("a.enc")).unwrap(), b"one");
        assert_eq!(std::fs::read(scratch.path("b.enc")).unwrap(), b"two");
        assert!(!scratch.path("c.enc").exists());
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_zero_chunks_writes_nothing() {
        let scratch = Scratch::new("enc_zero");
        write_bulk_encrypted_data(&bulk(&[]), &[scratch.path("a.txt")], None).unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_input_without_file_name() {
        let scratch = Scratch::new("enc_no_name");
        let out_dir = scratch.path("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let inputs = [scratch.path("a.txt"), PathBuf::from("..")];
        let data = bulk(&[b"one", b"two"]);
        let err = write_bulk_encrypted_data(&data, &inputs, Some(&out_dir)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid conversion: cannot get file name from input file .."
        );
        assert_eq!(std::fs::read(out_dir.join("a.enc")).unwrap(), b"one");
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_multiple_inputs_into_output_dir() {
        let scratch = Scratch::new("dec_multi_dir");
        let out_dir = scratch.path("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let inputs = [
            scratch.path("a.txt.enc"),
            scratch.path("b.enc"),
            scratch.path("c"),
        ];
        let data = bulk(&[b"first", b"second", b""]);
        write_bulk_decrypted_data(&data, &inputs, Some(&out_dir)).unwrap();
        assert_eq!(
            std::fs::read(out_dir.join("a.txt.plain")).unwrap(),
            b"first"
        );
        assert_eq!(std::fs::read(out_dir.join("b.plain")).unwrap(), b"second");
        assert_eq!(std::fs::read(out_dir.join("c.plain")).unwrap(), b"");
        assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 3);
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_multiple_inputs_without_output() {
        let scratch = Scratch::new("dec_multi_none");
        let inputs = [scratch.path("a.enc"), scratch.path("b.enc")];
        let data = bulk(&[b"alpha", b"beta"]);
        write_bulk_decrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(std::fs::read(scratch.path("a.plain")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(scratch.path("b.plain")).unwrap(), b"beta");
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_single_chunk_uses_output_file_as_is() {
        let scratch = Scratch::new("dec_single_out");
        let inputs = [scratch.path("a.enc")];
        let output = scratch.path("explicit.out");
        let data = bulk(&[b"only"]);
        write_bulk_decrypted_data(&data, &inputs, Some(&output)).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"only");
        assert!(!scratch.path("a.plain").exists());
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_single_chunk_without_output() {
        let scratch = Scratch::new("dec_single_none");
        let inputs = [scratch.path("a.enc")];
        let data = bulk(&[b"only"]);
        write_bulk_decrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(std::fs::read(scratch.path("a.plain")).unwrap(), b"only");
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_extra_inputs_are_ignored() {
        let scratch = Scratch::new("dec_extra");
        let inputs = [
            scratch.path("a.enc"),
            scratch.path("b.enc"),
            scratch.path("c.enc"),
        ];
        let data = bulk(&[b"one", b"two"]);
        write_bulk_decrypted_data(&data, &inputs, None).unwrap();
        assert_eq!(std::fs::read(scratch.path("a.plain")).unwrap(), b"one");
        assert_eq!(std::fs::read(scratch.path("b.plain")).unwrap(), b"two");
        assert!(!scratch.path("c.plain").exists());
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_zero_chunks_writes_nothing() {
        let scratch = Scratch::new("dec_zero");
        write_bulk_decrypted_data(&bulk(&[]), &[scratch.path("a.enc")], None).unwrap();
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_input_without_file_name() {
        let scratch = Scratch::new("dec_no_name");
        let out_dir = scratch.path("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let inputs = [scratch.path("a.enc"), PathBuf::from("..")];
        let data = bulk(&[b"one", b"two"]);
        let err = write_bulk_decrypted_data(&data, &inputs, Some(&out_dir)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid conversion: cannot get file name from input file .."
        );
        assert_eq!(std::fs::read(out_dir.join("a.plain")).unwrap(), b"one");
    }

    #[test]
    fn characterization_write_bulk_encrypted_data_fewer_inputs_than_chunks() {
        let scratch = Scratch::new("enc_few_inputs");
        let data = bulk(&[b"one", b"two"]);
        let err = write_bulk_encrypted_data(&data, &[scratch.path("a.txt")], None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid conversion: missing input file for chunk 1"
        );
        assert_eq!(std::fs::read(scratch.path("a.enc")).unwrap(), b"one");
    }

    #[test]
    fn characterization_write_bulk_decrypted_data_fewer_inputs_than_chunks() {
        let scratch = Scratch::new("dec_few_inputs");
        let data = bulk(&[b"one", b"two"]);
        let err = write_bulk_decrypted_data(&data, &[scratch.path("a.enc")], None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid conversion: missing input file for chunk 1"
        );
        assert_eq!(std::fs::read(scratch.path("a.plain")).unwrap(), b"one");
    }
}
