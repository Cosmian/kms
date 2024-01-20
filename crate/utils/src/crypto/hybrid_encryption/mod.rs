//! Hybrid encryption system based on either Elliptic Curve Integrated Encryption Scheme (ECIES) or PKCS#11 compatible key wrapping algorithms for RSA.
//! This module uses for ECIES:
//! - the `NaCL` Salsa Sealed Box encryption scheme, also found in libsodium. It is an hybrid encryption scheme using X25519 for the KEM and Salsa 20 Poly1305 for the DEM.
//! - the ECIES scheme with NIST and AES algorithms.
//! This module uses for PKCS#11 RSA hybrid encryption system the suite `Aes256Sha256`
//! These schemes do not support additional authenticated data.

mod decryption;
mod encryption;
mod rsa_oaep_aes_gcm;
pub use decryption::HybridDecryptionSystem;
pub use encryption::HybridEncryptionSystem;
