use super::kmip_operations::ErrorReason;
use crate::error::KmipError;

/// Structure used to encrypt with Covercrypt or ECIES
///
/// To encrypt some data with Covercrypt we need to
/// pass an access policy. The KMIP format do not provide
/// us a way to send this access policy with the plaintext
/// data to encrypt (in a vendor attribute for example).
/// We need to prepend the encoded access policy to the plaintext
/// bytes and decode them in the KMS code before encrypting with
/// Covercrypt. This struct is not useful (and shouldn't be use)
/// if the user ask to encrypt with something else than Cover Crypt
/// (for example an AES encrypt.) See also `DecryptedData` struct.
/// The binary format of this struct is:
/// 1. LEB128 unsigned length of encryption policy string in UTF8 encoded bytes
/// 2. encryption policy string in UTF8 encoded bytes
/// 3. LEB128 unsigned length of additional metadata
/// 4. additional metadata encrypted in the header by the DEM
/// 5. plaintext data to encrypt
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DataToEncrypt {
    pub encryption_policy: Option<String>,
    pub header_metadata: Option<Vec<u8>>,
    pub plaintext: Vec<u8>,
}

impl DataToEncrypt {
    /// Serialize the data to encrypt to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Write the encryption policy
        if let Some(encryption_policy) = &self.encryption_policy {
            let encryption_policy_bytes = encryption_policy.as_bytes();
            leb128::write::unsigned(&mut bytes, encryption_policy_bytes.len() as u64).unwrap();
            bytes.extend_from_slice(encryption_policy_bytes);
        } else {
            leb128::write::unsigned(&mut bytes, 0).unwrap();
        }
        // Write the metadata
        if let Some(metadata) = &self.header_metadata {
            leb128::write::unsigned(&mut bytes, metadata.len() as u64).unwrap();
            bytes.extend_from_slice(metadata);
        } else {
            leb128::write::unsigned(&mut bytes, 0).unwrap();
        }
        // Write the plaintext
        bytes.extend_from_slice(&self.plaintext);
        bytes
    }

    pub fn try_from_bytes(mut bytes: &[u8]) -> Result<Self, KmipError> {
        // Read the encryption policy
        let size_of_encryption_policy_in_bytes =
            leb128::read::unsigned(&mut bytes).map_err(|_| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    "expected a LEB128 encoded number (size of the encryption policy string) at \
                     the beginning of the data to encrypt."
                        .to_owned(),
                )
            })? as usize;
        // If the size of the encryption policy is 0, it means that there is no encryption policy
        let encryption_policy = if size_of_encryption_policy_in_bytes == 0 {
            None
        } else {
            let encryption_policy_bytes = bytes
                .take(..size_of_encryption_policy_in_bytes)
                .ok_or_else(|| {
                    KmipError::KmipError(
                        ErrorReason::Invalid_Message,
                        format!(
                            "size of encryption policy in bytes expected: \
                             {size_of_encryption_policy_in_bytes}, but only {} bytes available.",
                            bytes.len()
                        ),
                    )
                })?;
            // Decode the encryption policy string
            let encryption_policy_string = String::from_utf8(encryption_policy_bytes.to_owned())
                .map_err(|e| {
                    KmipError::KmipError(
                        ErrorReason::Invalid_Message,
                        format!("failed deserializing the encryption policy string: {e}",),
                    )
                })?;
            Some(encryption_policy_string)
        };

        // Read the metadata
        let size_of_metadata = leb128::read::unsigned(&mut bytes).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "expected a LEB128 encoded number (size of metadata) after the encryption policy."
                    .to_owned(),
            )
        })? as usize;
        // If the size of metadata is 0, then there is no metadata
        let metadata = if size_of_metadata == 0 {
            None
        } else {
            Some(
                bytes
                    .take(..size_of_metadata)
                    .ok_or_else(|| {
                        KmipError::KmipError(
                            ErrorReason::Invalid_Message,
                            format!(
                                "size of metadata in bytes expected: {size_of_metadata}, but only \
                                 {} bytes available.",
                                bytes.len()
                            ),
                        )
                    })?
                    .to_vec(),
            )
        };

        // Remaining is the plaintext to encrypt
        let plaintext = bytes.to_vec();

        Ok(Self {
            encryption_policy,
            header_metadata: metadata,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::DataToEncrypt;

    #[test]
    fn test_ser_de() {
        // full
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: Some("a && b".to_owned()),
                header_metadata: Some(String::from("äbcdef").into_bytes()),
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        }
        // empty header metadata
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: Some("a && b".to_owned()),
                header_metadata: None,
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        }
        // empty policy
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: None,
                header_metadata: Some(String::from("äbcdef").into_bytes()),
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        }
        // plaintext only
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: None,
                header_metadata: None,
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        }
    }
}
