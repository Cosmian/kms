use crate::kmip_2_1::{KmipOperation, kmip_types::Tag};

/// Policy governing client modification of attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeEditPolicy {
    /// Attribute is modifiable, subject to object permissions and validation.
    Allowed,
    /// Attribute is server-managed and read-only for this operation.
    ServerManaged,
    /// Modifying this attribute requires explicit operation authorization.
    RequiresGrant,
}

impl Tag {
    /// Edit restrictions for the four attribute-edit operations. Unlisted tags default
    /// to `Allowed`; new attributes still require policy review and object authorization.
    #[must_use]
    pub const fn edit_policy(self, operation: KmipOperation) -> AttributeEditPolicy {
        use AttributeEditPolicy::{Allowed, RequiresGrant, ServerManaged};
        use KmipOperation::{AddAttribute, DeleteAttribute};

        match (self, operation) {
            // Read-only attributes (KMIP 2.1 §4 rule tables: modifiable by server No,
            // modifiable by client No, deletable by client No) SHALL NOT be added
            // (§6.1.2), set (§6.1.51), modified (§6.1.34) or deleted (§6.1.13).
            (
                Self::ArchiveDate
                | Self::CertificateAttributes
                | Self::CertificateLength
                | Self::CertificateType
                | Self::CompromiseDate
                | Self::CompromiseOccurrenceDate
                | Self::CryptographicAlgorithm
                | Self::CryptographicDomainParameters
                | Self::CryptographicLength
                | Self::DestroyDate
                | Self::Digest
                | Self::DigitalSignatureAlgorithm
                | Self::InitialDate
                | Self::KeyFormatType
                | Self::KeyValuePresent
                | Self::NISTKeyType
                | Self::ObjectType
                | Self::OpaqueDataType
                | Self::OriginalCreationDate
                | Self::ProtectionStorageMasks
                | Self::RandomNumberGenerator
                | Self::RotateDate
                | Self::RotateGeneration
                | Self::ShortUniqueIdentifier
                | Self::UniqueIdentifier
                | Self::X509CertificateIdentifier
                | Self::X509CertificateIssuer
                | Self::X509CertificateSubject
                // Server-maintained, not modifiable by the client (§4.3, §4.24, §4.29,
                // §4.33, §4.57); `RotateLatest` is the keyset head the server moves.
                | Self::AlwaysSensitive
                | Self::Fresh
                | Self::LastChangeDate
                | Self::NeverExtractable
                | Self::RotateLatest
                | Self::State,
                _,
            )
            // Modifiable by client, but "Deletable by client: No".
            | (
                Self::CryptographicUsageMask
                | Self::ActivationDate
                | Self::DeactivationDate
                | Self::Sensitive
                | Self::Extractable,
                DeleteAttribute,
            )
            | (Self::RotateAutomatic, AddAttribute | DeleteAttribute) => ServerManaged,
            // Attributes that weaken or redirect key usage need ownership or an explicit grant
            // of the edit operation: a generic `Get` grant is not enough.
            (
                Self::Sensitive
                | Self::Extractable
                | Self::UsageLimits
                | Self::CryptographicUsageMask
                | Self::ActivationDate
                | Self::DeactivationDate
                | Self::Link
                | Self::LinkType
                | Self::RotateInterval
                | Self::RevocationReason,
                _,
            ) => RequiresGrant,
            _ => Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use AttributeEditPolicy::{Allowed, RequiresGrant, ServerManaged};

    use super::*;
    use crate::kmip_2_1::kmip_attributes::Attribute;

    #[test]
    fn legacy_attribute_index_keeps_original_tag_support() {
        assert_eq!(Attribute::AttributeIndex(1).tag(), None);
        assert!(matches!(
            serde_json::from_str::<Tag>("\"AttributeIndex\""),
            Err(error) if error.is_data()
        ));
    }

    /// A wrong `Attribute::tag` arm would silently apply another tag's policy.
    #[test]
    fn attribute_tag_matches_policy_tags() {
        use time::OffsetDateTime;

        use crate::{
            kmip_0::kmip_types::State,
            kmip_2_1::{
                kmip_objects::ObjectType,
                kmip_types::{
                    CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType,
                    NistKeyType, UniqueIdentifier,
                },
            },
        };

        let now = OffsetDateTime::UNIX_EPOCH;
        for (attribute, tag) in [
            (Attribute::AlwaysSensitive(true), Tag::AlwaysSensitive),
            (Attribute::NeverExtractable(true), Tag::NeverExtractable),
            (Attribute::RotateGeneration(1), Tag::RotateGeneration),
            (Attribute::RotateDate(now), Tag::RotateDate),
            (Attribute::RotateLatest(true), Tag::RotateLatest),
            (Attribute::RotateAutomatic(true), Tag::RotateAutomatic),
            (
                Attribute::UniqueIdentifier(UniqueIdentifier::TextString("uid".to_owned())),
                Tag::UniqueIdentifier,
            ),
            (
                Attribute::ObjectType(ObjectType::SymmetricKey),
                Tag::ObjectType,
            ),
            (
                Attribute::CryptographicLength(256),
                Tag::CryptographicLength,
            ),
            (Attribute::CertificateLength(2048), Tag::CertificateLength),
            (Attribute::InitialDate(now), Tag::InitialDate),
            (Attribute::Fresh(true), Tag::Fresh),
            (Attribute::LastChangeDate(now), Tag::LastChangeDate),
            (
                Attribute::OriginalCreationDate(now),
                Tag::OriginalCreationDate,
            ),
            (Attribute::State(State::Active), Tag::State),
            (Attribute::Sensitive(true), Tag::Sensitive),
            (Attribute::Extractable(true), Tag::Extractable),
            (
                Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                Tag::CryptographicAlgorithm,
            ),
            (
                Attribute::CryptographicDomainParameters(CryptographicDomainParameters::default()),
                Tag::CryptographicDomainParameters,
            ),
            (
                Attribute::KeyFormatType(KeyFormatType::Raw),
                Tag::KeyFormatType,
            ),
            (
                Attribute::NistKeyType(NistKeyType::PrivateSignatureKey),
                Tag::NISTKeyType,
            ),
            (Attribute::DestroyDate(now), Tag::DestroyDate),
            (
                Attribute::X509CertificateSubject("CN=x".to_owned()),
                Tag::X509CertificateSubject,
            ),
        ] {
            assert_eq!(attribute.tag(), Some(tag), "{attribute}");
        }
    }

    /// Expected policy per (tags, [Add, Set, Modify, Delete]).
    const MATRIX: &[(&[Tag], [AttributeEditPolicy; 4])] = &[
        (
            &[
                Tag::AlwaysSensitive,
                Tag::NeverExtractable,
                Tag::RotateGeneration,
                Tag::RotateDate,
                Tag::RotateLatest,
                Tag::UniqueIdentifier,
                Tag::ObjectType,
                Tag::CryptographicAlgorithm,
                Tag::CryptographicDomainParameters,
                Tag::CryptographicLength,
                Tag::CertificateType,
                Tag::CertificateLength,
                Tag::DigitalSignatureAlgorithm,
                Tag::Digest,
                Tag::KeyFormatType,
                Tag::NISTKeyType,
                Tag::ShortUniqueIdentifier,
                Tag::X509CertificateIdentifier,
                Tag::X509CertificateIssuer,
                Tag::X509CertificateSubject,
                Tag::ArchiveDate,
                Tag::CompromiseDate,
                Tag::DestroyDate,
                Tag::InitialDate,
                Tag::Fresh,
                Tag::LastChangeDate,
                Tag::OriginalCreationDate,
                Tag::State,
            ],
            [ServerManaged; 4],
        ),
        (
            &[
                Tag::CryptographicUsageMask,
                Tag::ActivationDate,
                Tag::DeactivationDate,
                Tag::Sensitive,
                Tag::Extractable,
            ],
            [RequiresGrant, RequiresGrant, RequiresGrant, ServerManaged],
        ),
        (
            &[Tag::RotateAutomatic],
            [ServerManaged, Allowed, Allowed, ServerManaged],
        ),
        (
            &[
                Tag::UsageLimits,
                Tag::Link,
                Tag::LinkType,
                Tag::RotateInterval,
                Tag::RevocationReason,
            ],
            [RequiresGrant; 4],
        ),
        (
            &[Tag::Comment, Tag::Name, Tag::CryptographicParameters],
            [Allowed; 4],
        ),
    ];

    #[test]
    fn edit_policy_matches_operation_rules() {
        use KmipOperation::{AddAttribute, DeleteAttribute, ModifyAttribute, SetAttribute};
        for (tags, expected) in MATRIX {
            for tag in *tags {
                let ops = [AddAttribute, SetAttribute, ModifyAttribute, DeleteAttribute];
                for (op, want) in ops.into_iter().zip(expected) {
                    assert_eq!(tag.edit_policy(op), *want, "{tag:?} / {op:?}");
                }
            }
        }
    }
}
