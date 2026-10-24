use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ProtocolVersion,
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{GetAttributeList, GetAttributeListResponse, GetAttributes},
        kmip_types::{AttributeReference, Tag, VendorAttributeReference},
    },
};
use cosmian_logger::trace;

use crate::{core::KMS, middlewares::UserId, result::KResult};

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

/// Attributes KMIP 1.x does not define; never listed to 1.x clients.
const KMIP2_ONLY: [Tag; 11] = [
    Tag::QuantumSafe,
    Tag::RotateAutomatic,
    Tag::RotateDate,
    Tag::RotateGeneration,
    Tag::RotateInterval,
    Tag::RotateLatest,
    Tag::RotateName,
    Tag::RotateOffset,
    Tag::NISTKeyType,
    Tag::PKCS12FriendlyName,
    Tag::ShortUniqueIdentifier,
];

/// Returns the names of all attributes currently set on the object.
pub(crate) async fn get_attribute_list(
    kms: &KMS,
    request: GetAttributeList,
    user: &UserId,
) -> KResult<GetAttributeListResponse> {
    get_attribute_list_with_protocol_version(kms, request, user, None).await
}

pub(crate) async fn get_attribute_list_with_protocol_version(
    kms: &KMS,
    request: GetAttributeList,
    user: &UserId,
    protocol_version: Option<ProtocolVersion>,
) -> KResult<GetAttributeListResponse> {
    // KMIP 1.x clients MUST NOT be told about attributes their protocol version does not
    // define. KMIP 2.x defines all of them, hence the `i32::MAX` fallback (which also
    // covers the version-agnostic call site).
    let kmip1_minor = protocol_version
        .as_ref()
        .filter(|pv| pv.protocol_version_major == 1)
        .map_or(i32::MAX, |pv| pv.protocol_version_minor);

    // The object's real attribute set, exactly as Get Attributes returns it
    // (this also performs the permission / existence check and resolves the object UID).
    let response = super::get::get_attributes(
        kms,
        GetAttributes {
            unique_identifier: request.unique_identifier,
            attribute_reference: None,
        },
        user,
    )
    .await?;
    let attrs = response.attributes;

    let mut refs: Vec<AttributeReference> = Vec::new();
    if let Some(vendor_attrs) = &attrs.vendor_attributes {
        refs.extend(vendor_attrs.iter().map(|va| {
            AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification: va.vendor_identification.clone(),
                attribute_name: va.attribute_name.clone(),
            })
        }));
    }

    // Standard attributes: TL-profile order first (XML profile vectors), then the rest.
    let mut tags: Vec<Tag> = Vec::new();
    for attribute in Vec::<Attribute>::from(attrs) {
        if let Some(tag) = attribute.tag() {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    tags.sort_by_key(|tag| {
        TL_PROFILE_ATTRIBUTES
            .iter()
            .position(|(t, _)| t == tag)
            .unwrap_or(usize::MAX)
    });
    for tag in tags {
        let introduced = TL_PROFILE_ATTRIBUTES
            .iter()
            .find(|(t, _)| *t == tag)
            .map_or_else(
                || i32::from(KMIP2_ONLY.contains(&tag)) * i32::MAX,
                |(_, m)| *m,
            );
        if kmip1_minor >= introduced {
            refs.push(AttributeReference::Standard(tag));
        }
    }

    let attribute_references = if refs.is_empty() { None } else { Some(refs) };

    if let Some(refs) = &attribute_references {
        trace!(
            target: "kmip",
            "get_attribute_list uid={} refs=[{}]",
            response.unique_identifier,
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
        unique_identifier: response.unique_identifier,
        attribute_references,
    })
}
