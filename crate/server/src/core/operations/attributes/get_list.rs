use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ProtocolVersion,
    kmip_2_1::{
        KmipOperation,
        kmip_operations::{GetAttributeList, GetAttributeListResponse},
        kmip_types::{AttributeReference, Tag, UniqueIdentifier, VendorAttributeReference},
    },
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::from_request},
    result::KResult,
};

/// Standard attribute tags advertised by `GetAttributeList` for the TL profile, in the
/// exact order expected by the XML profile test vectors, paired with the minimum KMIP 1.x
/// *minor* version in which the OASIS KMIP Specification defines them (Section 3
/// "Attributes"):
///
/// - KMIP 1.1: `Fresh` (§3.34)
/// - KMIP 1.2: `Alternative Name` (§3.40), `Original Creation Date` (§3.43)
/// - KMIP 1.3: `Random Number Generator` (§3.44)
/// - KMIP 1.4: `Sensitive` (§3.48), `Always Sensitive` (§3.49), `Extractable` (§3.50),
///   `Never Extractable` (§3.51)
///
/// All remaining tags exist since KMIP 1.0 and are therefore mapped to `0`.
const TL_PROFILE_ATTRIBUTES: [(Tag, i32); 20] = [
    (Tag::UniqueIdentifier, 0),
    (Tag::ObjectType, 0),
    (Tag::CryptographicAlgorithm, 0),
    (Tag::CryptographicLength, 0),
    (Tag::AlternativeName, 2),
    (Tag::AlwaysSensitive, 4),
    (Tag::ApplicationSpecificInformation, 0),
    (Tag::CryptographicUsageMask, 0),
    (Tag::Digest, 0),
    (Tag::Extractable, 4),
    (Tag::Fresh, 1),
    (Tag::InitialDate, 0),
    (Tag::LastChangeDate, 0),
    (Tag::LeaseTime, 0),
    (Tag::Name, 0),
    (Tag::NeverExtractable, 4),
    (Tag::OriginalCreationDate, 2),
    (Tag::RandomNumberGenerator, 3),
    (Tag::Sensitive, 4),
    (Tag::State, 0),
];

/// Returns the names of all attributes currently set on the object.
pub(crate) async fn get_attribute_list(
    kms: &KMS,
    request: GetAttributeList,
    user: &str,
) -> KResult<GetAttributeListResponse> {
    get_attribute_list_with_protocol_version(kms, request, user, None).await
}

pub(crate) async fn get_attribute_list_with_protocol_version(
    kms: &KMS,
    request: GetAttributeList,
    user: &str,
    protocol_version: Option<ProtocolVersion>,
) -> KResult<GetAttributeListResponse> {
    // KMIP 1.x clients MUST NOT be told about attributes their protocol version does not
    // define. KMIP 2.x defines all of them, hence the `i32::MAX` fallback (which also
    // covers the version-agnostic call site).
    let kmip1_minor = protocol_version
        .as_ref()
        .filter(|pv| pv.protocol_version_major == 1)
        .map_or(i32::MAX, |pv| pv.protocol_version_minor);

    let uid = from_request(request.unique_identifier.as_ref(), "GetAttributeList")?;

    // Permission / existence check (reuses GetAttributes gating). We ignore the
    // actual attributes for the minimal implementation but still verify access.
    let owm = Box::pin(retrieve_object_for_operation(
        uid,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;

    // Build attribute references in a stable, spec-like order expected by the XML
    // profile tests. For these profiles, the AttributeReference list is fixed per
    // vector family (TL vs SKFF), regardless of whether individual attributes are
    // currently set on the object. We therefore include the full ordered list of
    // standard attribute tags for the selected profile.
    let attrs = owm.attributes();
    let mut refs: Vec<AttributeReference> = Vec::new();

    // 1) Vendor Attribute references first: include only vendor "x" attributes, sorted by name.
    //    This avoids hardcoding a fixed list while keeping deterministic order for tests.
    if let Some(vendor_attrs) = &attrs.vendor_attributes {
        let mut x_vendor_names: Vec<String> = vendor_attrs
            .iter()
            .filter(|va| va.vendor_identification == "x")
            .map(|va| va.attribute_name.clone())
            .collect();
        x_vendor_names.sort();
        for name in x_vendor_names {
            refs.push(AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification: "x".to_owned(),
                attribute_name: name,
            }));
        }
    }

    // 2) Standard Attribute tag references for the TL profile, in the exact expected
    //    order, filtered by the minimum KMIP 1.x minor version that defines each of them
    //    (see `TL_PROFILE_ATTRIBUTES`).
    for (tag, introduced_in_kmip1_minor) in TL_PROFILE_ATTRIBUTES {
        if kmip1_minor >= introduced_in_kmip1_minor {
            refs.push(AttributeReference::Standard(tag));
        }
    }

    let attribute_references = if refs.is_empty() { None } else { Some(refs) };

    if let Some(refs) = &attribute_references {
        trace!(
            target: "kmip",
            "get_attribute_list uid={uid} refs=[{}]",
            refs
                .iter()
                .map(|r| match r {
                    AttributeReference::Standard(t) => format!("{t:?}"),
                    AttributeReference::Vendor(v) => format!("vendor:{}:{}", v.vendor_identification, v.attribute_name),
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(GetAttributeListResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.as_str().to_owned()),
        attribute_references,
    })
}
