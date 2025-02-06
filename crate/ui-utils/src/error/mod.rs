use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("{0}")]
    Default(String),
}

impl From<Vec<u8>> for UtilsError {
    fn from(value: Vec<u8>) -> Self {
        Self::Default(format!("Failed converting Vec<u8>: {value:?}"))
    }
}

impl From<base64::DecodeError> for UtilsError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Default(format!("Failed converting b64: {e:?}"))
    }
}
