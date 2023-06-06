use cosmian_kmip::kmip::{
    kmip_objects::ObjectType, kmip_operations::GetResponse as GetResponseRust,
};
use pyo3::{exceptions::PyException, prelude::*, types::PyBytes};

#[pyclass]
pub struct KmsObject(GetResponseRust);

impl KmsObject {
    pub fn new(get_response: GetResponseRust) -> Self {
        Self(get_response)
    }
}

#[pymethods]
impl KmsObject {
    /// Get the type of the underlying KMIP object.
    ///
    /// Returns:
    ///     str
    pub fn object_type(&self) -> &str {
        match self.0.object_type {
            ObjectType::Certificate => "Certificate",
            ObjectType::CertificateRequest => "CertificateRequest",
            ObjectType::SymmetricKey => "SymmetricKey",
            ObjectType::PublicKey => "PublicKey",
            ObjectType::PrivateKey => "PrivateKey",
            ObjectType::SplitKey => "SplitKey",
            ObjectType::SecretData => "SecretData",
            ObjectType::OpaqueObject => "OpaqueObject",
            ObjectType::PGPKey => "PGPKey",
        }
    }

    /// Retrieve key bytes
    ///
    /// Returns:
    ///     bytes
    pub fn key_block(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let key_bytes = self
            .0
            .object
            .key_block()
            .map_err(|e| PyException::new_err(e.to_string()))?
            .key_bytes()
            .map_err(|e| PyException::new_err(e.to_string()))?;

        Ok(PyBytes::new(py, &key_bytes).into())
    }
}
