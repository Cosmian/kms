use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct TeeParams {
    // contains the path to the sgx signer public key
    pub sgx_public_signer_key: Option<PathBuf>,
}
