use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
    kmip_2_1::kmip_operations::{Hash, HashResponse},
};
use cosmian_logger::trace;
use openssl::hash::{Hasher, MessageDigest};

use crate::{
    core::{
        KMS,
        operations::key_ops::multi_part::{Part, StreamOwner},
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

fn message_digest(algorithm: HashingAlgorithm) -> KResult<MessageDigest> {
    Ok(match algorithm {
        HashingAlgorithm::SHA224 => MessageDigest::sha224(),
        HashingAlgorithm::SHA256 => MessageDigest::sha256(),
        HashingAlgorithm::SHA384 => MessageDigest::sha384(),
        HashingAlgorithm::SHA512 => MessageDigest::sha512(),
        HashingAlgorithm::SHA3224 => MessageDigest::sha3_224(),
        HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
        HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
        HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
        algorithm => {
            kms_bail!(KmsError::NotSupported(format!(
                "Unsupported hashing algorithm: {algorithm:?}"
            )))
        }
    })
}

/// KMIP Hash, single-part or multi-part (KMIP 2.1 §6.1.24): the running digest state of a
/// multi-part hash is kept server-side under the returned Correlation Value.
pub(crate) async fn hash_operation(
    kms: &KMS,
    request: Hash,
    user: &UserId,
) -> KResult<HashResponse> {
    trace!(
        "algorithm={:?}, data_len={}",
        request.cryptographic_parameters.hashing_algorithm,
        request.data.as_ref().map_or(0, Vec::len)
    );

    let part = Part::classify(
        request.init_indicator,
        request.final_indicator,
        request.correlation_value.as_deref(),
    )?;
    let data: &[u8] = match (&request.data, part) {
        (Some(data), _) => data,
        (None, Part::Single) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "Hash: Data is required for a single-part operation".to_owned(),
            ));
        }
        (None, _) => &[],
    };
    let owner = StreamOwner {
        op: "Hash",
        user,
        key_uid: "",
    };
    let (data, correlation_value) = kms.multi_part.run(
        &kms.rng,
        part,
        owner,
        || {
            let algorithm = request
                .cryptographic_parameters
                .hashing_algorithm
                .ok_or_else(|| {
                    KmsError::InvalidRequest("Hashing algorithm is required".to_owned())
                })?;
            Ok(Hasher::new(message_digest(algorithm)?)?)
        },
        |hasher, last| {
            hasher.update(data)?;
            Ok(if last {
                Some(hasher.finish()?.to_vec())
            } else {
                None
            })
        },
    )?;

    Ok(HashResponse {
        data,
        correlation_value,
    })
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
        kmip_2_1::{kmip_operations::Hash, kmip_types::CryptographicParameters},
    };

    use crate::{
        error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms,
    };

    fn sha256_request(
        data: Option<&[u8]>,
        correlation_value: Option<Vec<u8>>,
        init_indicator: Option<bool>,
        final_indicator: Option<bool>,
    ) -> Hash {
        Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            },
            data: data.map(<[u8]>::to_vec),
            correlation_value,
            init_indicator,
            final_indicator,
        }
    }

    #[allow(clippy::unwrap_in_result)]
    #[tokio::test]
    async fn test_server_hash_operation() -> KResult<()> {
        let kms = test_kms().await?;

        let expected_hash = vec![
            253, 23, 128, 166, 252, 158, 224, 218, 178, 108, 235, 75, 57, 65, 171, 3, 230, 108,
            205, 151, 13, 29, 185, 22, 18, 198, 109, 244, 81, 91, 10, 10,
        ];

        // Single-part forms, including Init + Final without a Correlation Value (KMIP 2.1 §6.1)
        for (init_indicator, final_indicator) in [
            (None, None),
            (Some(false), None),
            (Some(false), Some(true)),
            (None, Some(true)),
            (Some(true), Some(true)),
        ] {
            let request = Hash {
                cryptographic_parameters: CryptographicParameters {
                    hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                    ..Default::default()
                },
                data: Some(vec![1, 2, 3]),
                correlation_value: None,
                init_indicator,
                final_indicator,
            };
            let response = kms.hash(request, &UserId::from("test")).await.unwrap();
            assert_eq!(response.data, Some(expected_hash.clone()));
            assert_eq!(response.correlation_value, None);
        }

        Ok(())
    }

    /// TC-STREAM-HASH-2-20: SHA-256 over "a" | "b" | "c" | "" equals SHA-256("abc").
    #[tokio::test]
    async fn test_server_hash_multi_part_known_answer() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("test");
        let abc_sha256 =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();

        let init = kms
            .hash(sha256_request(Some(b"a"), None, Some(true), None), &user)
            .await?;
        assert!(init.data.is_none());
        let cv = init.correlation_value.unwrap();
        for chunk in [b"b", b"c"] {
            let next = kms
                .hash(
                    sha256_request(Some(chunk), Some(cv.clone()), None, None),
                    &user,
                )
                .await?;
            assert!(next.data.is_none());
            assert_eq!(next.correlation_value.as_ref(), Some(&cv));
        }
        let last = kms
            .hash(
                sha256_request(Some(b""), Some(cv.clone()), None, Some(true)),
                &user,
            )
            .await?;
        assert_eq!(last.data, Some(abc_sha256));
        assert!(last.correlation_value.is_none());

        // The stream is closed; an unknown Correlation Value is rejected.
        let err = kms
            .hash(
                sha256_request(Some(b"d"), Some(cv), None, Some(true)),
                &user,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Invalid_Correlation_Value, _)
        ));
        Ok(())
    }

    #[allow(clippy::unwrap_in_result)]
    #[tokio::test]
    async fn test_server_hash_operation_with_correlation() -> KResult<()> {
        let kms = test_kms().await?;

        // Init Indicator combined with a Correlation Value is invalid
        let request = sha256_request(
            Some(&[1, 2, 3]),
            Some(vec![4, 5, 6]),
            Some(true),
            Some(true),
        );
        kms.hash(request, &UserId::from("test")).await.unwrap_err();

        // Test different hashing algorithms
        for algorithm in [
            HashingAlgorithm::SHA384,
            HashingAlgorithm::SHA512,
            HashingAlgorithm::SHA3224,
            HashingAlgorithm::SHA3384,
            HashingAlgorithm::SHA3512,
        ] {
            let request = Hash {
                cryptographic_parameters: CryptographicParameters {
                    hashing_algorithm: Some(algorithm),
                    ..Default::default()
                },
                data: Some(vec![1, 2, 3]),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            };
            let response = kms.hash(request, &UserId::from("test")).await.unwrap();
            assert!(response.data.is_some());
            assert_eq!(response.correlation_value, None);
        }

        // Data is required for a single-part Hash (KMIP 2.1 §6.1.24, Table 235)
        let err = kms
            .hash(
                sha256_request(None, None, None, None),
                &UserId::from("test"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
        ));

        // Test invalid request (missing algorithm)
        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: None,
                ..Default::default()
            },
            data: Some(vec![1, 2, 3]),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        kms.hash(request, &UserId::from("test")).await.unwrap_err();

        Ok(())
    }

    /// SHA-224 is a KMIP 2.1 Hashing Algorithm: FIPS 180-4 known answer for "abc".
    #[tokio::test]
    async fn test_server_hash_sha224_known_answer() -> KResult<()> {
        let kms = test_kms().await?;
        let request = Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA224),
                ..Default::default()
            },
            data: Some(b"abc".to_vec()),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        };
        let response = kms.hash(request, &UserId::from("test")).await?;
        assert_eq!(
            response.data,
            Some(hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7").unwrap())
        );
        Ok(())
    }
}
