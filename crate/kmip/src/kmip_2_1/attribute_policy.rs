use crate::kmip_2_1::{KmipOperation, kmip_attributes::Attribute, kmip_types::Tag};

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
    /// Edit restriction this KMS applies to the attribute under one of the four
    /// attribute-edit operations; other operations are not meaningful here.
    ///
    /// `Allowed` leaves per-attribute validation and object permissions in force.
    #[must_use]
    pub const fn edit_policy(self, operation: KmipOperation) -> AttributeEditPolicy {
        use AttributeEditPolicy::{Allowed, RequiresGrant, ServerManaged};
        use KmipOperation::{AddAttribute, DeleteAttribute, ModifyAttribute, SetAttribute};

        match (self, operation) {
            (
                Self::AlwaysSensitive
                | Self::NeverExtractable
                | Self::RotateGeneration
                | Self::RotateDate
                | Self::RotateLatest,
                _,
            )
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
                ModifyAttribute | DeleteAttribute,
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

impl Attribute {
    /// Edit restriction for this attribute; vendor attributes carry no standard tag and are unrestricted.
    #[must_use]
    pub const fn edit_policy(&self, operation: KmipOperation) -> AttributeEditPolicy {
        match self.tag() {
            Some(tag) => tag.edit_policy(operation),
            None => AttributeEditPolicy::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use AttributeEditPolicy::{Allowed, RequiresGrant, ServerManaged};

    use super::*;

    /// Expected policy per (tag, [Add, Set, Modify, Delete]), transcribed from the guards this table replaced.
    const MATRIX: &[(Tag, [AttributeEditPolicy; 4])] = &[
        (Tag::AlwaysSensitive, [ServerManaged; 4]),
        (Tag::NeverExtractable, [ServerManaged; 4]),
        (Tag::RotateGeneration, [ServerManaged; 4]),
        (Tag::RotateDate, [ServerManaged; 4]),
        (Tag::RotateLatest, [ServerManaged; 4]),
        (
            Tag::UniqueIdentifier,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::ObjectType,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::CryptographicLength,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::CertificateLength,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::Digest,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::InitialDate,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (Tag::Fresh, [Allowed, Allowed, ServerManaged, ServerManaged]),
        (
            Tag::LastChangeDate,
            [Allowed, Allowed, ServerManaged, ServerManaged],
        ),
        (
            Tag::OriginalCreationDate,
            [Allowed, Allowed, ServerManaged, ServerManaged],
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
