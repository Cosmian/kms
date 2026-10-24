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
    ///
    /// KMIP 2.1 §6.1.2: read-only attributes SHALL NOT be added.
    #[must_use]
    pub const fn edit_policy(self, operation: KmipOperation) -> AttributeEditPolicy {
        use AttributeEditPolicy::{Allowed, RequiresGrant, ServerManaged};
        use KmipOperation::{AddAttribute, DeleteAttribute, ModifyAttribute, SetAttribute};

        match (self, operation) {
            // Sensitivity history is server-managed (KMIP 2.1 4.3 and 4.33).
            (
                Self::AlwaysSensitive
                | Self::NeverExtractable
                | Self::RotateGeneration
                | Self::RotateDate
                | Self::RotateLatest,
                _,
            )
            | (
                // Read-only metadata: KMIP 2.1 4.15, 4.21, 4.25; Set follows 6.1.51.
                Self::UniqueIdentifier
                | Self::ObjectType
                | Self::CryptographicLength
                | Self::CertificateLength
                | Self::Digest
                | Self::InitialDate
                | Self::Fresh
                | Self::LastChangeDate
                | Self::OriginalCreationDate
                | Self::State
                // KMIP 2.1 §4: "Modifiable by client: No / Deletable by client: No".
                | Self::CryptographicAlgorithm
                | Self::KeyFormatType
                | Self::ArchiveDate
                | Self::CompromiseDate
                | Self::DestroyDate
                | Self::CertificateType
                | Self::KeyValuePresent
                | Self::OpaqueDataType
                | Self::X509CertificateIdentifier
                | Self::X509CertificateIssuer
                | Self::X509CertificateSubject,
                AddAttribute | SetAttribute | ModifyAttribute | DeleteAttribute,
            )
            // Modifiable by client, but "Deletable by client: No".
            | (
                Self::CryptographicUsageMask
                | Self::DigitalSignatureAlgorithm
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
            kmip_2_1::{kmip_objects::ObjectType, kmip_types::UniqueIdentifier},
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
            ],
            [ServerManaged; 4],
        ),
        (
            &[
                Tag::UniqueIdentifier,
                Tag::ObjectType,
                Tag::CryptographicLength,
                Tag::CertificateLength,
                Tag::Digest,
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
                Tag::CryptographicAlgorithm,
                Tag::KeyFormatType,
                Tag::ArchiveDate,
                Tag::CompromiseDate,
                Tag::DestroyDate,
                Tag::CertificateType,
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
        (&[Tag::Comment, Tag::Name], [Allowed; 4]),
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
