use thiserror::Error;

pub type RbacResult<T> = Result<T, RbacError>;

#[derive(Error, Debug)]
pub enum RbacError {
    #[error("RBAC policy evaluation error: {0}")]
    PolicyEvaluation(String),

    #[error("RBAC policy file error: {0}")]
    PolicyFile(String),

    #[error("RBAC serialization error: {0}")]
    Serialization(String),

    #[error("RBAC external OPA error: {0}")]
    ExternalOpa(String),
}

impl From<serde_json::Error> for RbacError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for RbacError {
    fn from(e: std::io::Error) -> Self {
        Self::PolicyFile(e.to_string())
    }
}
