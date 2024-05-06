use cosmian_kmip::kmip::kmip_operations::{EncryptResponse, GetResponse};
use pyo3::{exceptions::PyException, prelude::*, types::PyBytes};

#[pyclass]
pub struct KmsObject(pub GetResponse);

#[pymethods]
impl KmsObject {
    /// Gets the type of the underlying KMIP object.
    ///
    /// Returns:
    ///     str
    pub fn object_type(&self) -> String {
        self.0.object_type.to_string()
    }

    /// Retrieves key bytes
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

#[pyclass]
pub struct KmsEncryptResponse(pub EncryptResponse);

#[pymethods]
impl KmsEncryptResponse {
    /// Reads a KmsEncryptResponse from a JSON string.
    #[staticmethod]
    pub fn from_json(data: &str) -> PyResult<Self> {
        Ok(Self(
            serde_json::from_str(data).map_err(|e| PyException::new_err(e.to_string()))?,
        ))
    }

    /// Retrieves uid of the key used during encryption
    ///
    /// Returns:
    ///     String
    pub fn unique_identifier(&self) -> String {
        self.0.unique_identifier.to_string()
    }

    /// Retrieves data bytes
    ///
    /// Returns:
    ///     bytes
    pub fn data(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = self.0.data.clone().unwrap_or_default();
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Retrieves IV, Counter, or Nonce bytes
    ///
    /// Returns:
    ///     bytes
    pub fn iv_counter_nonce(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = self.0.iv_counter_nonce.clone().unwrap_or_default();
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Retrieves authentication tag bytes
    ///
    /// Returns:
    ///     bytes
    pub fn authenticated_encryption_tag(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = self
            .0
            .authenticated_encryption_tag
            .clone()
            .unwrap_or_default();
        Ok(PyBytes::new(py, &bytes).into())
    }

    /// Retrieves correlation value bytes
    ///
    /// Returns:
    ///     bytes
    pub fn correlation_value(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = self.0.correlation_value.clone().unwrap_or_default();
        Ok(PyBytes::new(py, &bytes).into())
    }
}
