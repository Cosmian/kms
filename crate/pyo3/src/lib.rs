#![allow(non_local_definitions)]
use pyo3::prelude::*;

mod py_kms_client;
mod py_kms_object;

use py_kms_client::KmsClient;
use py_kms_object::{KmsEncryptResponse, KmsObject};

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn cosmian_kms(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<KmsClient>()?;
    m.add_class::<KmsObject>()?;
    m.add_class::<KmsEncryptResponse>()?;
    Ok(())
}
