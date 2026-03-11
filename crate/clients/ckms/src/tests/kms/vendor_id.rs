//! E2E test: verify that KMIP `VendorAttribute` entries use the vendor ID
//! configured on the server, not the hard-coded `"cosmian"` default.

use cosmian_kms_cli::reexport::cosmian_kmip::kmip_2_1::{
    extra::{
        VENDOR_ID_COSMIAN,
        tagging::{SYSTEM_TAG_SYMMETRIC_KEY, VENDOR_ATTR_TAG},
    },
    kmip_operations::GetAttributes,
    kmip_types::{AttributeReference, CryptographicAlgorithm, Tag, UniqueIdentifier},
    requests::symmetric_key_create_request,
};
use test_kms_server::{
    AuthenticationOptions, BuildServerParamsOptions, MainDBConfig, build_server_params_full,
    start_test_server_with_options,
};

use crate::error::result::CosmianResult;

const TEST_VENDOR_ID: &str = "test_vendor_id";
/// Port offset +6 from `DEFAULT_KMS_SERVER_PORT` (9998); free for this dedicated test.
const TEST_PORT: u16 = 9998 + 6;

/// Verify that a KMS server configured with a custom `vendor_identification`
/// stores KMIP `VendorAttribute` entries under that custom vendor ID rather
/// than the default `"cosmian"` one.
#[tokio::test]
pub(crate) async fn test_vendor_id_in_vendor_attributes() -> CosmianResult<()> {
    // 1. Build server params with a custom vendor_identification.
    //    `BuildServerParamsOptions` has no `vendor_identification` field, so we
    //    mutate the returned `ServerParams` directly.
    let mut server_params = build_server_params_full(BuildServerParamsOptions {
        db_config: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            ..MainDBConfig::default()
        },
        port: TEST_PORT,
        ..Default::default()
    })?;
    server_params.vendor_identification = TEST_VENDOR_ID.to_owned();

    // 2. Start the test KMS server.  The `db_config` first argument is ignored
    //    when `AuthenticationOptions.server_params` is `Some`.
    let mut ctx = start_test_server_with_options(
        MainDBConfig::default(),
        TEST_PORT,
        AuthenticationOptions {
            server_params: Some(server_params),
            ..Default::default()
        },
        None,
        None,
    )
    .await?;

    // 3. Override the client's vendor_id to match the server's custom value.
    ctx.owner_client_config.vendor_id = TEST_VENDOR_ID.to_owned();
    let client = ctx.get_owner_client();

    // 4. Create a symmetric key.  Tags are persisted server-side as
    //    VendorAttributes using the server's configured vendor_identification.
    let create_request = symmetric_key_create_request(
        TEST_VENDOR_ID,
        None,
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        false,
        None,
    )?;
    let create_response = client.create(create_request).await?;
    let uid = create_response.unique_identifier.to_string();

    // 5. Retrieve all attributes for the created key, explicitly requesting
    //    Tag::Tag so the server serializes the tag vendor attributes in the
    //    response (by default the server omits them to avoid leaking internals).
    let get_attrs_response = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid)),
            attribute_reference: Some(vec![AttributeReference::Standard(Tag::Tag)]),
        })
        .await?;
    let attributes = &get_attrs_response.attributes;

    // 6. At least one VendorAttribute must carry our custom vendor ID.
    let vendor_attrs = attributes
        .vendor_attributes
        .as_ref()
        .expect("a newly created symmetric key must have VendorAttributes");

    let has_test_vendor = vendor_attrs.iter().any(|va| {
        va.vendor_identification == TEST_VENDOR_ID && va.attribute_name == VENDOR_ATTR_TAG
    });
    assert!(
        has_test_vendor,
        "Expected a VendorAttribute with vendor_identification={TEST_VENDOR_ID} \
         and attribute_name={VENDOR_ATTR_TAG}; got: {vendor_attrs:?}"
    );

    // 7. The system tag `_kk` (symmetric key marker) must be visible when
    //    querying tags under TEST_VENDOR_ID.
    let tags = attributes.get_tags(TEST_VENDOR_ID);
    assert!(
        tags.contains(SYSTEM_TAG_SYMMETRIC_KEY),
        "System tag {SYSTEM_TAG_SYMMETRIC_KEY} must appear under vendor_id \
         {TEST_VENDOR_ID}; got tags: {tags:?}"
    );

    // 8. No tags should appear under the default "cosmian" vendor ID — the
    //    server is not using that vendor ID.
    let cosmian_tags = attributes.get_tags(VENDOR_ID_COSMIAN);
    assert!(
        cosmian_tags.is_empty(),
        "Tags must NOT be stored under the default vendor ID {VENDOR_ID_COSMIAN} \
         when the server uses {TEST_VENDOR_ID}; got: {cosmian_tags:?}"
    );

    ctx.stop_server().await?;
    Ok(())
}
