use crate::{Deserializer, Serializer, error::KmipError, kmip_0::kmip_types::ErrorReason};

/// Structure used to encrypt with Covercrypt or ECIES
///
/// To encrypt some data with Covercrypt we need to pass an access policy. The
/// KMIP format do not provide us a way to send this access policy with the
/// plaintext data to encrypt (in a vendor attribute for example).  We need to
/// prepend the encoded access policy to the plaintext bytes and decode them in
/// the KMS code before encrypting with Covercrypt. This struct is not useful
/// (and shouldn't be use) if the user ask to encrypt with something else than
/// Cover Crypt (for example an AES encrypt.) See also `DecryptedData` struct.
/// The binary format of this struct is: 1. LEB128 unsigned length of encryption
/// policy string in UTF8 encoded bytes 2. encryption policy string in UTF8
/// encoded bytes 3. LEB128 unsigned length of additional metadata 4. additional
/// metadata encrypted in the header by the DEM 5. plaintext data to encrypt
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DataToEncrypt {
    pub encryption_policy: Option<String>,
    pub plaintext: Vec<u8>,
}

impl DataToEncrypt {
    /// Serialize the data to encrypt to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, KmipError> {
        // Compute the size of the buffer
        let mut mem_size = 1 // for encryption policy
            + 1 // for metadata
            + self.plaintext.len();
        if let Some(encryption_policy) = &self.encryption_policy {
            mem_size += encryption_policy.len();
        }

        // Write the encryption policy
        let mut se = Serializer::with_capacity(mem_size);
        if let Some(encryption_policy) = &self.encryption_policy {
            se.write_vec(encryption_policy.as_bytes())?;
        } else {
            se.write_leb128_u64(0)?;
        }
        // Write the plaintext
        let mut bytes = se.finalize().to_vec();
        bytes.extend_from_slice(&self.plaintext);
        Ok(bytes)
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, KmipError> {
        let mut de = Deserializer::new(bytes);

        // Read the encryption policy
        let encryption_policy = de
            .read_vec()
            .map(|ep| (!ep.is_empty()).then_some(ep))
            .and_then(|ep| {
                ep.map(|ep| {
                    String::from_utf8(ep).map_err(|e| {
                        KmipError::Kmip21(
                            ErrorReason::Invalid_Message,
                            format!("failed deserializing the encryption policy string: {e}"),
                        )
                    })
                })
                .transpose()
            })
            .map_err(|e| {
                KmipError::ConversionError(format!("failed deserializing data to encrypt: {e}"))
            })?;

        // Remaining is the plaintext to encrypt
        let plaintext = de.finalize();

        Ok(Self {
            encryption_policy,
            plaintext,
        })
    }
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::DataToEncrypt;

    #[test]
    fn test_ser_de() {
        // full
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: Some("a && b".to_owned()),
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes().unwrap();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        };
        // empty header metadata
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: Some("a && b".to_owned()),
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes().unwrap();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        };
        // empty policy
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: None,
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes().unwrap();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        };
        // plaintext only
        {
            let data_to_encrypt = DataToEncrypt {
                encryption_policy: None,
                plaintext: String::from("this is a plain text à è ").into_bytes(),
            };
            let bytes = data_to_encrypt.to_bytes().unwrap();
            let data_to_encrypt_full_deserialized = DataToEncrypt::try_from_bytes(&bytes).unwrap();
            assert_eq!(data_to_encrypt, data_to_encrypt_full_deserialized);
        }
    }
}
