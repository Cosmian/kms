// //! AWS KMS is a managed service that can't be run locally for tests. By its design, private key materials never leave the AWS HSM, which makes it even harder to make tests that do not involve
// //! actual calls to external infrastructure. Therefore, to verify the correct behavior of the AWS KMS BYOK import and export commands, we will unwrap using openssl.
// //! As long as we can trust AWS KMS to behave correctly, we can consider these functions viable to verify the unwrapping process.
// //!
// //! If ever E2E tests with AWS KMS are to be implemented, simply edit the calls to the functions below to calls to AWS KMS `import-key-material` command.
// use openssl::cipher::{Cipher, CipherRef};
// use openssl::cipher_ctx::CipherCtx;
// use openssl::pkey::{PKey, Private, Public};
// use openssl::rsa::Padding;
// use openssl::{encrypt::Decrypter, hash::MessageDigest};

// /// Generate SM2 keypair using OpenSSL
// /// This replaces the chinese AWS KMS keypair generation for testing purposes.
// #[cfg(feature = "non-fips")]
// pub(crate) fn generate_sm2_keypair()
// -> Result<(PKey<Private>, PKey<Public>), Box<dyn std::error::Error>> {
//     use openssl::ec::{EcGroup, EcKey};
//     use openssl::nid::Nid;

//     let group = EcGroup::from_curve_name(Nid::SM2)?;

//     // Generate EC key on SM2 curve
//     let ec_key = EcKey::generate(&group)?;

//     // Convert to PKey
//     let private_key = PKey::from_ec_key(ec_key.clone())?;

//     // Extract public key
//     let public_ec_key = EcKey::from_public_key(&group, ec_key.public_key())?;
//     let public_key = PKey::from_ec_key(public_ec_key)?;

//     Ok((private_key, public_key))
// }

// /// Unwrap (decrypt) the given ciphertext using SM2PKE (SM2 Public Key Encryption)
// /// SM2PKE is a Chinese national standard encryption algorithm used in AWS China regions.
// /// This replaces the AWS KMS Import key material step for testing purposes.
// ///
// /// Note: SM2 support requires OpenSSL 1.1.1+ compiled with SM2 support.
// /// This is typically available in non-FIPS mode only.
// #[cfg(feature = "non-fips")]
// pub(crate) fn sm2pke_unwrap(
//     ciphertext: &[u8],
//     private_key: &PKey<Private>,
// ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     // Verify the key is an SM2 key

//     use openssl::pkey_ctx::PkeyCtx;
//     if private_key.id() != openssl::pkey::Id::SM2 {
//         return Err("Private key is not an SM2 key".into());
//     }

//     // Create decryption context
//     let mut ctx = PkeyCtx::new(private_key)?;
//     ctx.decrypt_init()?;

//     // Calculate buffer size for decryption
//     let buffer_len = ctx.decrypt(ciphertext, None)?;
//     let mut plaintext = vec![0_u8; buffer_len];

//     // Perform decryption
//     let plaintext_len = ctx.decrypt(ciphertext, Some(&mut plaintext))?;
//     plaintext.truncate(plaintext_len);

//     Ok(plaintext)
// }
