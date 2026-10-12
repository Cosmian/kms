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
            // Add retains legacy initialization behavior, not a blanket KMIP allowance.
            | (
                Self::UniqueIdentifier
                | Self::ObjectType
                | Self::CryptographicLength
                | Self::CertificateLength
                | Self::Digest
                | Self::InitialDate
                | Self::Fresh
                | Self::LastChangeDate
                | Self::OriginalCreationDate,
                SetAttribute | ModifyAttribute | DeleteAttribute,
            )
            // Add rejects `State` later with a different error, so it is not listed for Add.
            | (Self::State, SetAttribute | ModifyAttribute | DeleteAttribute)
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
        assert!(serde_json::from_str::<Tag>("\"AttributeIndex\"").is_err());
    }

    /// Expected policy per (tag, [Add, Set, Modify, Delete]), transcribed from the guards this table replaced.
    const MATRIX: &[(Tag, [AttributeEditPolicy; 4])] = &[
        (Tag::AlwaysSensitive, [ServerManaged; 4]),
        (Tag::NeverExtractable, [ServerManaged; 4]),
        (Tag::RotateGeneration, [ServerManaged; 4]),
        (Tag::RotateDate, [ServerManaged; 4]),
        (Tag::RotateLatest, [ServerManaged; 4]),
        (
            Tag::UniqueIdentifier,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::ObjectType,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::CryptographicLength,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::CertificateLength,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::Digest,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::InitialDate,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::Fresh,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::LastChangeDate,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::OriginalCreationDate,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::State,
            [Allowed, ServerManaged, ServerManaged, ServerManaged],
        ),
        (
            Tag::RotateAutomatic,
            [ServerManaged, Allowed, Allowed, ServerManaged],
        ),
        (
            Tag::Sensitive,
            [RequiresGrant, RequiresGrant, RequiresGrant, ServerManaged],
        ),
        (
            Tag::Extractable,
            [RequiresGrant, RequiresGrant, RequiresGrant, ServerManaged],
        ),
        (Tag::Comment, [Allowed; 4]),
        (Tag::Name, [Allowed; 4]),
        (Tag::Link, [Allowed; 4]),
        (Tag::LinkType, [Allowed; 4]),
    ];

    #[test]
    fn edit_policy_matches_previous_guards() {
        use KmipOperation::{AddAttribute, DeleteAttribute, ModifyAttribute, SetAttribute};
        for (tag, expected) in MATRIX {
            let ops = [AddAttribute, SetAttribute, ModifyAttribute, DeleteAttribute];
            for (op, want) in ops.into_iter().zip(expected) {
                assert_eq!(tag.edit_policy(op), *want, "{tag:?} / {op:?}");
            }
        }
    }
}
