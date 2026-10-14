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
