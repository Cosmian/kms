#![allow(clippy::unwrap_in_result)]

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            BatchErrorContinuationOption, BlockCipherMode, ErrorReason, HashingAlgorithm,
            MessageExtension, ProtocolVersion, ResultStatusEnumeration,
        },
    },
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Check, Decrypt, Encrypt, MAC, Operation, RNGRetrieve},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, OperationEnumeration,
            RecommendedCurve, UniqueIdentifier,
        },
        requests::{create_ec_key_pair_request, symmetric_key_create_request},
    },
    ttlv::to_ttlv,
};
use cosmian_logger::{debug, log_init};

use crate::{error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms};

#[tokio::test]
async fn test_kmip_mac_messages() -> KResult<()> {
    // Disable most logging
    log_init(Some("warn"));

    let kms = test_kms().await?;
    let owner = UserId::from("eyJhbGciOiJSUzI1Ni");

    let symmetric_key_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::HMACSHA3512,
        EMPTY_TAGS,
        false,
        None,
    )?;

    let unique_identifier = Some(
        kms.create(symmetric_key_request, &owner)
            .await?
            .unique_identifier,
    );
    let mac_request = MAC {
        unique_identifier,
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA3512),
            ..Default::default()
        }),
        data: Some(vec![0; 32]),
        ..Default::default()
    };

    // prepare and send the single message
    let items_number = 10_000;
    let items: Vec<RequestMessageBatchItemVersioned> = (0..items_number)
        .map(|_| {
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::MAC(
                mac_request.clone(),
            )))
        })
        .collect();
    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            maximum_response_size: None,
            batch_count: items_number,
            ..Default::default()
        },
        batch_item: items,
    };

    let response = kms.message(message_request, &owner).await?;
    assert_eq!(response.response_header.batch_count, items_number);
    // Check that all operations succeeded
    for item in &response.batch_item {
        let ResponseMessageBatchItemVersioned::V21(item) = item else {
            panic!("not a V21 response");
        };
        assert_eq!(item.result_status, ResultStatusEnumeration::Success);
        assert_eq!(item.operation, Some(OperationEnumeration::MAC));
        assert!(matches!(
            item.response_payload,
            Some(Operation::MACResponse(_))
        ));
    }
    assert_eq!(
        response.batch_item.len(),
        usize::try_from(items_number).unwrap()
    );

    log_init(option_env!("RUST_LOG"));
    Ok(())
}

#[tokio::test]
async fn test_batch_error_continuation() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("batch-error-continuation@example.com");
    let create_request = || {
        symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )
    };
    let failed_check = || {
        Operation::Check(Check {
            unique_identifier: Some(UniqueIdentifier::TextString("missing-key".to_owned())),
            usage_limits_count: None,
            cryptographic_usage_mask: None,
            lease_time: None,
        })
    };

    let stop_response = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    client_correlation_value: Some("default-stop".to_owned()),
                    batch_count: 2,
                    ..Default::default()
                },
                batch_item: vec![
                    RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                        failed_check(),
                    )),
                    RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                        Operation::Create(create_request()?),
                    )),
                ],
            },
            &owner,
        )
        .await?;
    assert_eq!(stop_response.batch_item.len(), 1);
    assert_eq!(
        stop_response
            .response_header
            .client_correlation_value
            .as_deref(),
        Some("default-stop")
    );

    let continue_response = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_error_continuation_option: Some(BatchErrorContinuationOption::Continue),
                    batch_count: 2,
                    ..Default::default()
                },
                batch_item: vec![
                    RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                        failed_check(),
                    )),
                    RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                        Operation::Create(create_request()?),
                    )),
                ],
            },
            &owner,
        )
        .await?;
    assert_eq!(continue_response.batch_item.len(), 2);
    let ResponseMessageBatchItemVersioned::V21(item) = &continue_response.batch_item[1] else {
        panic!("not a V21 response");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);
    Ok(())
}

#[tokio::test]
async fn message_rejects_mismatched_batch_count() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("invalid-batch-count@example.com");
    let result = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: 2,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(
                    RequestMessageBatchItem::new(Operation::Check(Check {
                        unique_identifier: None,
                        usage_limits_count: None,
                        cryptographic_usage_mask: None,
                        lease_time: None,
                    })),
                )],
            },
            &owner,
        )
        .await;
    if !matches!(
        result,
        Err(KmsError::Kmip21Error(ErrorReason::Invalid_Message, _))
    ) {
        return Err(KmsError::Default(
            "mismatched BatchCount was accepted".to_owned(),
        ));
    }
    Ok(())
}

#[tokio::test]
async fn message_rejects_unsupported_critical_extension() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("critical-extension@example.com");
    let mut item = RequestMessageBatchItem::new(Operation::Check(Check {
        unique_identifier: None,
        usage_limits_count: None,
        cryptographic_usage_mask: None,
        lease_time: None,
    }));
    item.message_extension = Some(vec![MessageExtension {
        vendor_identification: "test.vendor".to_owned(),
        criticality_indicator: true,
        vendor_extension: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::VendorExtension {},
    }]);
    let response = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: 1,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(item)],
            },
            &owner,
        )
        .await?;
    let [ResponseMessageBatchItemVersioned::V21(item)] = response.batch_item.as_slice() else {
        return Err(KmsError::Default(
            "critical extension response did not contain one KMIP 2.1 batch item".to_owned(),
        ));
    };
    if item.result_status != ResultStatusEnumeration::OperationFailed
        || item.result_reason != Some(ErrorReason::Unknown_Message_Extension)
        || item.result_message.as_deref()
            != Some("critical message extension from vendor 'test.vendor' is not supported")
    {
        return Err(KmsError::Default(
            "critical MessageExtension did not reject the full message".to_owned(),
        ));
    }
    Ok(())
}

#[tokio::test]
async fn test_encrypt_kmip_messages() -> KResult<()> {
    // Disable most logging
    log_init(Some("warn"));
    let kms = test_kms().await?;
    let owner = UserId::from("eyJhbGciOiJSUzI1Ni");
    // Create a symmetric key first

    let symmetric_key_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;

    let unique_identifier = Some(
        kms.create(symmetric_key_request, &owner)
            .await?
            .unique_identifier,
    );

    let encrypt_request = Encrypt {
        unique_identifier: unique_identifier.clone(),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::XTS),
            ..Default::default()
        }),
        data: Some(vec![0_u8; 32].into()),
        i_v_counter_nonce: Some(vec![0_u8; 16]),
        ..Default::default()
    };

    // prepare and send multiple encrypt requests
    let items_number = 10_000;
    let items: Vec<RequestMessageBatchItemVersioned> = (0..items_number)
        .map(|_| {
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Encrypt(
                Box::new(encrypt_request.clone()),
            )))
        })
        .collect();

    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: items_number,
            ..Default::default()
        },
        batch_item: items,
    };

    let response = kms.message(message_request, &owner).await?;
    assert_eq!(response.response_header.batch_count, items_number);
    assert_eq!(
        response.batch_item.len(),
        usize::try_from(items_number).unwrap()
    );

    // Check that all operations succeeded
    for item in response.batch_item {
        let ResponseMessageBatchItemVersioned::V21(item) = item else {
            panic!("not a V21 response");
        };
        assert_eq!(item.result_status, ResultStatusEnumeration::Success);
        assert_eq!(item.operation, Some(OperationEnumeration::Encrypt));
        assert!(matches!(
            item.response_payload,
            Some(Operation::EncryptResponse(_))
        ));
    }

    log_init(option_env!("RUST_LOG"));
    Ok(())
}

#[tokio::test]
async fn ephemeral_encrypt_omits_ciphertext() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("ephemeral-encrypt@example.com");
    let created = kms
        .create(
            symmetric_key_create_request(
                VENDOR_ID_COSMIAN,
                None,
                256,
                CryptographicAlgorithm::AES,
                EMPTY_TAGS,
                false,
                None,
            )?,
            &owner,
        )
        .await?;
    let mut batch_item = RequestMessageBatchItem::new(Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: Some(created.unique_identifier),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        data: Some(vec![0_u8; 16].into()),
        ..Default::default()
    })));
    batch_item.ephemeral = Some(true);
    let response = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: 1,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(batch_item)],
            },
            &owner,
        )
        .await?;
    let [ResponseMessageBatchItemVersioned::V21(batch_item)] = response.batch_item.as_slice()
    else {
        return Err(KmsError::Default(
            "ephemeral Encrypt did not return one KMIP 2.1 batch item".to_owned(),
        ));
    };
    if !matches!(batch_item.response_payload, Some(Operation::EncryptResponse(ref response)) if response.data.is_none())
    {
        return Err(KmsError::Default(
            "ephemeral Encrypt returned ciphertext".to_owned(),
        ));
    }
    Ok(())
}

#[tokio::test]
async fn maximum_response_size_applies_to_rng_retrieve() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("response-size@example.com");
    let response = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    maximum_response_size: Some(1),
                    batch_count: 1,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(
                    RequestMessageBatchItem::new(Operation::RNGRetrieve(RNGRetrieve {
                        data_length: 32,
                    })),
                )],
            },
            &owner,
        )
        .await?;
    let [ResponseMessageBatchItemVersioned::V21(batch_item)] = response.batch_item.as_slice()
    else {
        return Err(KmsError::Default(
            "response-size test did not return one KMIP 2.1 batch item".to_owned(),
        ));
    };
    if batch_item.result_status != ResultStatusEnumeration::OperationFailed
        || batch_item.result_reason != Some(ErrorReason::Response_Too_Large)
        || batch_item.response_payload.is_some()
    {
        return Err(KmsError::Default(format!(
            "Maximum Response Size result: status={:?}, reason={:?}, payload={}",
            batch_item.result_status,
            batch_item.result_reason,
            batch_item.response_payload.is_some(),
        )));
    }
    Ok(())
}

#[tokio::test]
async fn negative_maximum_response_size_is_rejected() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("negative-response-size@example.com");
    let err = kms
        .message(
            RequestMessage {
                request_header: RequestMessageHeader {
                    maximum_response_size: Some(-1),
                    batch_count: 1,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(
                    RequestMessageBatchItem::new(Operation::Check(Check {
                        unique_identifier: None,
                        usage_limits_count: None,
                        cryptographic_usage_mask: None,
                        lease_time: None,
                    })),
                )],
            },
            &owner,
        )
        .await
        .expect_err("a negative MaximumResponseSize must be rejected");
    assert!(matches!(
        err,
        KmsError::Kmip21Error(ErrorReason::Invalid_Field, _)
    ));
    Ok(())
}

#[tokio::test]
async fn duplicate_create_reports_object_already_exists() -> KResult<()> {
    let kms = test_kms().await?;
    let owner = UserId::from("duplicate-create@example.com");
    let key_id = UniqueIdentifier::TextString("duplicate-create-key".to_owned());
    let request = || {
        symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            Some(key_id.clone()),
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )
    };
    let first = kms.create(request()?, &owner);
    let second = kms.create(request()?, &owner);
    let ((Ok(_), Err(err)) | (Err(err), Ok(_))) = tokio::join!(first, second) else {
        return Err(KmsError::Default(
            "concurrent Creates with the same identifier must have one success and one failure"
                .to_owned(),
        ));
    };
    if !matches!(
        err,
        KmsError::Kmip21Error(ErrorReason::Object_Already_Exists, _)
    ) {
        return Err(KmsError::Default(format!(
            "duplicate Create returned unexpected error: {err:?}"
        )));
    }

    if kms
        .database
        .retrieve_object("duplicate-create-key")
        .await?
        .is_none()
    {
        return Err(KmsError::Default(
            "the successful concurrent Create did not retain its object".to_owned(),
        ));
    }
    Ok(())
}
#[tokio::test]
async fn test_kmip_messages() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let kms = test_kms().await?;
    let owner = UserId::from("eyJhbGciOiJSUzI1Ni");

    // request key pair creation
    let ec_create_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::CURVE25519,
        false,
        None,
    )?;

    // prepare and send the single message
    let batch_item = vec![
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
            Operation::CreateKeyPair(Box::new(ec_create_request)),
        )),
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Locate(
            Box::default(),
        ))),
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Decrypt(
            Box::new(Decrypt {
                unique_identifier: Some(UniqueIdentifier::TextString("id_12345".to_owned())),
                data: Some(b"decrypted_data".to_vec()),
                ..Default::default()
            }),
        ))),
    ];
    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            batch_count: 3,
            ..Default::default()
        },
        batch_item,
    };
    debug!("message_request: {:#?}", to_ttlv(&message_request));

    let response = kms.message(message_request, &owner).await?;
    assert_eq!(response.response_header.batch_count, 3);
    assert_eq!(response.batch_item.len(), 3);

    // 1. Create keypair
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("not a V21 response");
    };
    assert_eq!(
        batch_item.operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::CreateKeyPairResponse(create_keypair_response)) =
        &batch_item.response_payload
    else {
        panic!("not a create key pair response payload");
    };

    // 2. Locate
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[1] else {
        panic!("not a V21 response");
    };
    assert_eq!(batch_item.operation, Some(OperationEnumeration::Locate));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "result_status: {:?}, result_message: {:?}, result_reason: {:?}",
        batch_item.result_status,
        batch_item.result_message,
        batch_item.result_reason
    );
    let Some(Operation::LocateResponse(locate_response)) = &batch_item.response_payload else {
        panic!("not a locate response payload");
    };
    // locate response contains only 2 keys, the pair that was created
    // by the first batch item, because processing is sequential and order is preserved
    assert_eq!(locate_response.located_items, Some(2));
    let locate_uids = locate_response.unique_identifier.clone().unwrap();
    assert_eq!(locate_uids.len(), 2);
    assert!(locate_uids.contains(&create_keypair_response.private_key_unique_identifier));
    assert!(locate_uids.contains(&create_keypair_response.public_key_unique_identifier));

    // 3. Decrypt (that failed)
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[2] else {
        panic!("not a V21 response");
    };

    assert_eq!(batch_item.operation, Some(OperationEnumeration::Decrypt));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        batch_item.result_message,
        Some("Decrypt: failed to retrieve the key: id_12345".to_owned())
    );
    assert_eq!(batch_item.result_reason, Some(ErrorReason::Item_Not_Found));
    assert!(batch_item.response_payload.is_none());
    Ok(())
}
