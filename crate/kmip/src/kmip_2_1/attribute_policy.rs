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
            // Read-only metadata: KMIP 2.1 4.15, 4.21, 4.25; Set follows 6.1.51.
            // Add retains legacy rules, including State's later handler rejection.
            | (
                Self::UniqueIdentifier
                | Self::ObjectType
                | Self::CryptographicLength
                | Self::CertificateLength
                | Self::Digest
                | Self::InitialDate
                | Self::Fresh
                | Self::LastChangeDate
                | Self::OriginalCreationDate
                | Self::State,
                SetAttribute | ModifyAttribute | DeleteAttribute,
            )
            | (Self::RotateAutomatic, AddAttribute | DeleteAttribute)
            | (Self::Sensitive | Self::Extractable, DeleteAttribute) => ServerManaged,
            (Self::Sensitive | Self::Extractable, _) => RequiresGrant,
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
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            &[Tag::RotateAutomatic],
            [ServerManaged, Allowed, Allowed, ServerManaged],
        ),
        (
            &[Tag::Sensitive, Tag::Extractable],
            [RequiresGrant, RequiresGrant, RequiresGrant, ServerManaged],
        ),
        (
            &[Tag::Comment, Tag::Name, Tag::Link, Tag::LinkType],
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
