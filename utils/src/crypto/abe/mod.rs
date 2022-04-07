use abe_gpsw::error::FormatErr;

use crate::error::LibError;

pub mod attributes;
pub mod ciphers;
pub mod kmip_requests;
pub mod locate;
pub mod master_keys;
pub mod secret_key;
pub mod user_key;

impl From<FormatErr> for LibError {
    fn from(e: FormatErr) -> Self {
        LibError::CryptographicError("ABE".to_owned(), e.to_string())
    }
}
