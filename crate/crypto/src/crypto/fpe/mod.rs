mod alphabet;
pub use alphabet::{Alphabet, AlphabetPreset};

pub(crate) mod ff1;

mod integer;
pub use integer::Integer;

mod float;
pub use float::Float;

mod error;
pub use error::FPEError;

#[cfg(test)]
mod tests;

/// The Key Length: 256 bit = 32 bytes for AES 256
pub const KEY_LENGTH: usize = 32;
