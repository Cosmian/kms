//! Tests for the server-managed `AlwaysSensitive` attribute (KMIP 2.1 §4.3).
//!
//! The `AlwaysSensitive` attribute is:
//! - created by the server (True iff the object was created `Sensitive`);
//! - read-only to clients (cannot be added, set, modified or deleted);
//! - permanently set to False once `Sensitive` has ever been set to False.
#![allow(clippy::unwrap_used, clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_interfaces::UserId;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attribute,
        kmip_operations::{
            AddAttribute, DeleteAttribute, GetAttributes, GetAttributesResponse, ModifyAttribute,
            SetAttribute,
        },
        kmip_types::{AttributeReference, CryptographicAlgorithm, Tag, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;

use crate::{
    config::ServerParams, core::KMS, error::KmsError, result::KResult,
    tests::test_utils::https_clap_config,
};

const USER: &str = "alwayssensitive_user";

async fn instantiate_kms() -> KResult<Arc<KMS>> {
    let clap_config = https_clap_config();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?,
    ))
}

async fn create_sym_key(kms: &Arc<KMS>, sensitive: bool) -> KResult<String> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        sensitive,
        None,
    )?;
    Ok(kms
        .create(request, &UserId::from(USER))
        .await?
        .unique_identifier
        .to_string())
}

async fn get_attributes(kms: &Arc<KMS>, uid: &str, tag: Tag) -> KResult<GetAttributesResponse> {
    kms.get_attributes(
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: Some(vec![AttributeReference::Standard(tag)]),
        },
        &UserId::from(USER),
    )
    .await
}

fn assert_read_only(result: &KResult<impl std::fmt::Debug>) {
    match result {
        Err(KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _)) => {}
        other => panic!("expected Attribute_Read_Only error, got: {other:?}"),
    }
}

/// A Sensitive object is created with `AlwaysSensitive = true`; a non-sensitive
/// one with `AlwaysSensitive = false` (KMIP 2.1 §4.3).
#[tokio::test]
async fn test_always_sensitive_set_at_creation() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;

    let sensitive_uid = create_sym_key(&kms, true).await?;
    let response = get_attributes(&kms, &sensitive_uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    let plain_uid = create_sym_key(&kms, false).await?;
    let response = get_attributes(&kms, &plain_uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    Ok(())
}

/// `AlwaysSensitive` is server-managed: clients cannot Add, Set, Modify or
/// Delete it (KMIP 2.1 §4.3, Table 34).
#[tokio::test]
async fn test_always_sensitive_is_read_only() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let uid = create_sym_key(&kms, true).await?;

    let add = kms
        .add_attribute(
            AddAttribute {
                unique_identifier: UniqueIdentifier::TextString(uid.clone()),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            &UserId::from(USER),
        )
        .await;
    assert_read_only(&add);

    let set = kms
        .set_attribute(
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            &UserId::from(USER),
        )
        .await;
    assert_read_only(&set);

    let modify = kms
        .modify_attribute(
            ModifyAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::AlwaysSensitive(false),
            },
            &UserId::from(USER),
        )
        .await;
    assert_read_only(&modify);

    let delete_by_value = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: Some(Attribute::AlwaysSensitive(true)),
                attribute_references: None,
            },
            &UserId::from(USER),
        )
        .await;
    assert_read_only(&delete_by_value);

    let delete_by_ref = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: None,
                attribute_references: Some(vec![AttributeReference::Standard(
                    Tag::AlwaysSensitive,
                )]),
            },
            &UserId::from(USER),
        )
        .await;
    assert_read_only(&delete_by_ref);

    // The value must be unchanged after all rejected attempts.
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    Ok(())
}

/// Setting `Sensitive` to False permanently clears `AlwaysSensitive`, even if
/// `Sensitive` is later set back to True (KMIP 2.1 §4.3).
#[tokio::test]
async fn test_always_sensitive_derived_from_sensitive_changes() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let uid = create_sym_key(&kms, true).await?;

    // Initially always-sensitive.
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(true));

    // Set Sensitive = false -> AlwaysSensitive becomes false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Sensitive(false),
        },
        &UserId::from(USER),
    )
    .await?;
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    // Set Sensitive = true again -> AlwaysSensitive stays false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Sensitive(true),
        },
        &UserId::from(USER),
    )
    .await?;
    let response = get_attributes(&kms, &uid, Tag::AlwaysSensitive).await?;
    assert_eq!(response.attributes.always_sensitive, Some(false));

    Ok(())
}

/// A non-owner with only a Get grant cannot delete or modify Sensitive attribute
/// to bypass sensitive export protection (GHSA-c75c-3cmm-48h7).
#[tokio::test]
async fn test_sensitive_cannot_be_stripped_with_only_get_grant() -> KResult<()> {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_operations::{DeleteAttribute, Get},
    };

    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let alice = UserId::from("alice");
    let bob = UserId::from("bob");

    // Alice creates a sensitive key.
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        true,
        None,
    )?;
    let response = kms.create(request, &alice).await?;
    let uid = response.unique_identifier.to_string();

    // Alice grants Bob only Get permission.
    kms.database
        .grant_operations(&uid, &bob, HashSet::from([KmipOperation::Get]))
        .await?;

    // Bob Get -> denied because key is sensitive and unwrapped.
    let get_req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        key_wrapping_specification: None,
        key_compression_type: None,
        key_format_type: None,
        key_wrap_type: None,
    };
    let err = kms.get(get_req.clone(), &bob).await.unwrap_err();
    assert!(matches!(
        err,
        KmsError::Kmip21Error(ErrorReason::Sensitive, _)
    ));

    // Bob attempts to DeleteAttribute(Sensitive) by value -> denied.
    let del_by_val = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: Some(Attribute::Sensitive(true)),
                attribute_references: None,
            },
            &bob,
        )
        .await;
    assert!(matches!(
        del_by_val,
        Err(KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _))
    ));

    // Bob attempts to DeleteAttribute(Sensitive) by tag reference -> denied.
    let del_by_ref = kms
        .delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                current_attribute: None,
                attribute_references: Some(vec![AttributeReference::Standard(Tag::Sensitive)]),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        del_by_ref,
        Err(KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _))
    ));

    // Bob attempts to SetAttribute(Sensitive(false)) -> denied.
    let set_res = kms
        .set_attribute(
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::Sensitive(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        set_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Bob attempts to ModifyAttribute(Sensitive(false)) -> denied.
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
        AddAttribute, ModifyAttribute,
    };
    let mod_res = kms
        .modify_attribute(
            ModifyAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::Sensitive(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        mod_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Bob attempts to AddAttribute(Sensitive(false)) -> denied.
    let add_res = kms
        .add_attribute(
            AddAttribute {
                unique_identifier: UniqueIdentifier::TextString(uid.clone()),
                new_attribute: Attribute::Sensitive(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        add_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Bob attempts to SetAttribute(Extractable(false)) -> denied.
    let set_ext_res = kms
        .set_attribute(
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::Extractable(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        set_ext_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Bob attempts to ModifyAttribute(Extractable(false)) -> denied.
    let mod_ext_res = kms
        .modify_attribute(
            ModifyAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::Extractable(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        mod_ext_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Bob attempts to AddAttribute(Extractable(false)) -> denied.
    let add_ext_res = kms
        .add_attribute(
            AddAttribute {
                unique_identifier: UniqueIdentifier::TextString(uid.clone()),
                new_attribute: Attribute::Extractable(false),
            },
            &bob,
        )
        .await;
    assert!(matches!(
        add_ext_res,
        Err(KmsError::Kmip21Error(ErrorReason::Permission_Denied, _))
    ));

    // Now Alice grants Bob explicit SetAttribute and ModifyAttribute rights.
    kms.database
        .grant_operations(
            &uid,
            &bob,
            HashSet::from([
                KmipOperation::Get,
                KmipOperation::SetAttribute,
                KmipOperation::ModifyAttribute,
            ]),
        )
        .await?;

    // With explicit SetAttribute grant, Bob can now set Sensitive(false).
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Sensitive(false),
        },
        &bob,
    )
    .await?;

    // Now Bob Get succeeds because Sensitive is false.
    let get_resp = kms.get(get_req, &bob).await?;
    assert_eq!(get_resp.unique_identifier.to_string(), uid);

    Ok(())
}

/// Keys marked Extractable=false cannot be exported in plaintext or wrapped form,
/// NeverExtractable latches server-side, and client-supplied NeverExtractable values
/// are overridden at creation time (GHSA-8mmx-f92q-2gq8).
#[tokio::test]
async fn test_extractable_and_never_extractable_enforcement() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_data_structures::KeyWrappingSpecification,
        kmip_operations::{CreateResponse, Get},
    };

    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let user = UserId::from(USER);

    // 1. Create a key with Extractable=false and attempt to pass conflicting NeverExtractable=false.
    // The server MUST override NeverExtractable to true at creation.
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::requests::symmetric_key_create_request;
    let mut create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        false,
        None,
    )?;
    create_req.attributes.extractable = Some(false);
    create_req.attributes.never_extractable = Some(false); // conflicting client value
    let CreateResponse {
        unique_identifier, ..
    } = kms.create(create_req.clone(), &user).await?;
    let uid = unique_identifier.to_string();

    // Verify NeverExtractable is true (unconditionally initialized server-side).
    let response = get_attributes(&kms, &uid, Tag::NeverExtractable).await?;
    assert_eq!(
        response.attributes.never_extractable,
        Some(true),
        "NeverExtractable must be initialized to true when Extractable is false"
    );

    // Also test Import with conflicting Extractable=false and NeverExtractable=false:
    // the server must unconditionally initialize NeverExtractable to true.
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_objects::ObjectType, kmip_operations::Import,
        requests::create_symmetric_key_kmip_object,
    };
    let mut import_attrs = create_req.attributes.clone();
    import_attrs.unique_identifier = None;
    import_attrs.extractable = Some(false);
    import_attrs.never_extractable = Some(false);
    let import_obj =
        create_symmetric_key_kmip_object(VENDOR_ID_COSMIAN, &[0x42; 32], &import_attrs)?;
    let import_res = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::default(),
                object_type: ObjectType::SymmetricKey,
                object: import_obj,
                attributes: import_attrs,
                key_wrap_type: None,
                replace_existing: None,
            },
            &user,
        )
        .await?;
    let import_uid = import_res.unique_identifier.to_string();
    let import_resp = get_attributes(&kms, &import_uid, Tag::NeverExtractable).await?;
    assert_eq!(
        import_resp.attributes.never_extractable,
        Some(true),
        "Imported symmetric key must initialize NeverExtractable to true when Extractable is false"
    );
    // 2. Get with no wrapping spec -> rejected with Not_Extractable.
    let get_req_plain = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        key_wrapping_specification: None,
        key_compression_type: None,
        key_format_type: None,
        key_wrap_type: None,
    };
    let err_plain = kms.get(get_req_plain, &user).await.unwrap_err();
    assert!(
        matches!(
            err_plain,
            KmsError::Kmip21Error(ErrorReason::Not_Extractable, _)
        ),
        "expected Not_Extractable on unwrapped Get, got: {err_plain:?}"
    );

    // 3. Get WITH wrapping spec -> still rejected with Not_Extractable.
    let get_req_wrapped = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        key_wrapping_specification: Some(KeyWrappingSpecification::default()),
        key_compression_type: None,
        key_format_type: None,
        key_wrap_type: None,
    };
    let err_wrapped = kms.get(get_req_wrapped, &user).await.unwrap_err();
    assert!(
        matches!(
            err_wrapped,
            KmsError::Kmip21Error(ErrorReason::Not_Extractable, _)
        ),
        "expected Not_Extractable even with wrapping spec, got: {err_wrapped:?}"
    );

    // 4. Latch behavior: Set Extractable=true -> NeverExtractable latches to false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Extractable(true),
        },
        &user,
    )
    .await?;
    let resp = get_attributes(&kms, &uid, Tag::NeverExtractable).await?;
    assert_eq!(
        resp.attributes.never_extractable,
        Some(false),
        "NeverExtractable must transition to false when Extractable becomes true"
    );

    // Set Extractable=false again -> NeverExtractable must STAY false.
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            new_attribute: Attribute::Extractable(false),
        },
        &user,
    )
    .await?;
    let resp = get_attributes(&kms, &uid, Tag::NeverExtractable).await?;
    assert_eq!(
        resp.attributes.never_extractable,
        Some(false),
        "NeverExtractable must latch to false and never revert to true"
    );

    // Defensive latch check: If an object somehow has NeverExtractable=true while
    // Extractable is absent/true, export must STILL be denied with Not_Extractable.
    let defensive_key = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        false,
        None,
    )?;
    let defensive_res = kms.create(defensive_key, &user).await?;
    let def_uid = defensive_res.unique_identifier.to_string();
    // Simulate legacy/corrupted state in database: Extractable=None, NeverExtractable=true
    let mut def_attrs = kms
        .database
        .retrieve_object(&def_uid)
        .await?
        .unwrap()
        .attributes()
        .clone();
    def_attrs.extractable = None;
    def_attrs.never_extractable = Some(true);
    let tags = def_attrs.get_tags(VENDOR_ID_COSMIAN);
    let def_obj = kms
        .database
        .retrieve_object(&def_uid)
        .await?
        .unwrap()
        .object()
        .clone();
    kms.database
        .update_object(&def_uid, &def_obj, &def_attrs, Some(&tags))
        .await?;
    let def_get = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(def_uid)),
        key_wrapping_specification: None,
        key_compression_type: None,
        key_format_type: None,
        key_wrap_type: None,
    };
    let def_err = kms.get(def_get, &user).await.unwrap_err();
    assert!(
        matches!(
            def_err,
            KmsError::Kmip21Error(ErrorReason::Not_Extractable, _)
        ),
        "defensive latch branch must return Not_Extractable, got: {def_err:?}"
    );
    // 5. Rekey: Rekeying a previously-extractable key
    // (Extractable=false, NeverExtractable=false) into a currently non-extractable replacement
    // re-initializes NeverExtractable to true for the new key.
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ReKey;
    let rekey_res = kms
        .rekey(
            ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                offset: None,
                attributes: None,
                protection_storage_masks: None,
            },
            &user,
        )
        .await?;
    let new_uid = rekey_res.unique_identifier.to_string();
    let new_resp = get_attributes(&kms, &new_uid, Tag::NeverExtractable).await?;
    assert_eq!(
        new_resp.attributes.never_extractable,
        Some(true),
        "ReKey fresh symmetric key must initialize NeverExtractable to true when Extractable is false"
    );

    Ok(())
}

/// PKCS#12 export of a sensitive private key must reject dummy/empty wrapping specs
/// that supply no encryption key password information.
#[tokio::test]
async fn test_pkcs12_sensitive_export_requires_non_empty_password() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::KeyWrappingSpecification,
        kmip_operations::{Certify, Get},
        kmip_types::{
            CertificateAttributes, EncryptionKeyInformation, KeyFormatType, WrappingMethod,
        },
    };
    log_init(option_env!("RUST_LOG"));
    let kms = instantiate_kms().await?;
    let user = UserId::from(USER);

    // Generate an RSA keypair with private key marked Sensitive=true.
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::requests::create_rsa_key_pair_request;
    let kp_req = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        Vec::<String>::new(),
        2048,
        true,
        None,
    )?;
    let kp_res = kms.create_key_pair(kp_req, &user).await?;

    let sk_uid = kp_res.private_key_unique_identifier.to_string();
    let pk_uid = kp_res.public_key_unique_identifier.clone();

    // Export private key directly as PKCS#12 with dummy wrapping spec (no encryption key info) -> denied Sensitive.
    let dummy_wrapping_spec = KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: None,
        ..Default::default()
    };
    let req = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(sk_uid.clone())),
        key_wrapping_specification: Some(dummy_wrapping_spec.clone()),
        key_compression_type: None,
        key_format_type: Some(KeyFormatType::PKCS12),
        key_wrap_type: None,
    };
    let err = kms.get(req, &user).await.unwrap_err();
    assert!(
        matches!(err, KmsError::Kmip21Error(ErrorReason::Sensitive, _)),
        "PKCS#12 with dummy wrapping spec must be denied Sensitive, got: {err:?}"
    );

    // Export private key directly with empty password UID -> denied Sensitive.
    let empty_pw_spec = KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(String::new()),
            cryptographic_parameters: None,
        }),
        ..Default::default()
    };
    let req2 = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(sk_uid.clone())),
        key_wrapping_specification: Some(empty_pw_spec),
        key_compression_type: None,
        key_format_type: Some(KeyFormatType::PKCS12),
        key_wrap_type: None,
    };
    let err2 = kms.get(req2, &user).await.unwrap_err();
    assert!(
        matches!(err2, KmsError::Kmip21Error(ErrorReason::Sensitive, _)),
        "PKCS#12 with empty password must be denied Sensitive, got: {err2:?}"
    );

    // Export certificate target (which links to the sensitive private key) as PKCS#12
    let cert_attrs = Attributes {
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(
            "C=FR, O=KMS Test, CN=Cert Sensitive PKCS12",
        )?),
        ..Default::default()
    };
    let cert_res = kms
        .certify(
            Certify {
                unique_identifier: Some(pk_uid),
                attributes: Some(cert_attrs),
                ..Certify::default()
            },
            &user,
        )
        .await?;
    let cert_uid = cert_res.unique_identifier.to_string();

    let req_cert = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(cert_uid)),
        key_wrapping_specification: Some(dummy_wrapping_spec),
        key_compression_type: None,
        key_format_type: Some(KeyFormatType::PKCS12),
        key_wrap_type: None,
    };
    let err_cert = kms.get(req_cert, &user).await.unwrap_err();
    assert!(
        matches!(err_cert, KmsError::Kmip21Error(ErrorReason::Sensitive, _)),
        "Certificate->linked sensitive private key PKCS#12 export with dummy wrapping spec must be denied Sensitive, got: {err_cert:?}"
    );
    Ok(())
}
