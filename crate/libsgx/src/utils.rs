use std::{
    fs::File,
    io::{BufReader, Read},
    mem,
};

use tracing::info;

use crate::{error::SgxError, quote::TargetInfo};

fn _is_running_inside_enclave() -> Result<bool, SgxError> {
    info!("/dev/attestation/my_target_info");
    let mut reader = BufReader::new(File::open("/dev/attestation/my_target_info")?);
    let info_size = mem::size_of::<TargetInfo>();
    let mut buffer = Vec::new();
    let size = reader.read_to_end(&mut buffer)?;

    Ok(size == info_size)
}

/// Check if the current program is running inside an enclave
pub fn is_running_inside_enclave() -> bool {
    _is_running_inside_enclave().unwrap_or(false)
}
