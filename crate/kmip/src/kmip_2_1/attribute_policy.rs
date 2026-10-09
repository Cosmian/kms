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
    /// Returns the edit policy for this attribute tag under the given operation.
    ///
    /// Returns `None` if the tag is not a supported attribute or if the operation
    /// is not an attribute edit operation (`AddAttribute`, `SetAttribute`,
    /// `ModifyAttribute`, `DeleteAttribute`).
    #[must_use]
    pub fn edit_policy(self, operation: KmipOperation) -> Option<AttributeEditPolicy> {
        if !matches!(
            operation,
            KmipOperation::AddAttribute
                | KmipOperation::SetAttribute
                | KmipOperation::ModifyAttribute
                | KmipOperation::DeleteAttribute
        ) {
            return None;
        }

        if !self.is_supported_attribute() {
            return None;
        }

        // 1. Attributes server-managed across all edit operations.
        if matches!(
            self,
            Self::AlwaysSensitive
                | Self::NeverExtractable
                | Self::RotateGeneration
                | Self::RotateDate
                | Self::RotateLatest
        ) {
            return Some(AttributeEditPolicy::ServerManaged);
        }

        // 2. Attributes read-only on Modify and Delete, but client-settable on Add and Set.
        if matches!(
            self,
            Self::UniqueIdentifier
                | Self::ObjectType
                | Self::CryptographicLength
                | Self::CertificateLength
                | Self::Digest
                | Self::InitialDate
                | Self::Fresh
                | Self::LastChangeDate
                | Self::OriginalCreationDate
        ) {
            return match operation {
                KmipOperation::ModifyAttribute | KmipOperation::DeleteAttribute => {
                    Some(AttributeEditPolicy::ServerManaged)
                }
                KmipOperation::AddAttribute | KmipOperation::SetAttribute => {
                    Some(AttributeEditPolicy::Allowed)
                }
                _ => None,
            };
        }

        // 3. State: read-only on Set, Modify, Delete.
        // AddAttribute preserves its post-retrieval local rejection returning InvalidRequest.
        if self == Self::State {
            return match operation {
                KmipOperation::SetAttribute
                | KmipOperation::ModifyAttribute
                | KmipOperation::DeleteAttribute => Some(AttributeEditPolicy::ServerManaged),
                KmipOperation::AddAttribute => Some(AttributeEditPolicy::Allowed),
                _ => None,
            };
        }

        // 4. RotateAutomatic: server-managed on Add and Delete, modifiable on Set and Modify.
        if self == Self::RotateAutomatic {
            return match operation {
                KmipOperation::AddAttribute | KmipOperation::DeleteAttribute => {
                    Some(AttributeEditPolicy::ServerManaged)
                }
                KmipOperation::SetAttribute | KmipOperation::ModifyAttribute => {
                    Some(AttributeEditPolicy::Allowed)
                }
                _ => None,
            };
        }

        // 5. Sensitive and Extractable: requires grant on Add/Set/Modify, read-only on Delete.
        if matches!(self, Self::Sensitive | Self::Extractable) {
            return match operation {
                KmipOperation::AddAttribute
                | KmipOperation::SetAttribute
                | KmipOperation::ModifyAttribute => Some(AttributeEditPolicy::RequiresGrant),
                KmipOperation::DeleteAttribute => Some(AttributeEditPolicy::ServerManaged),
                _ => None,
            };
        }

        Some(AttributeEditPolicy::Allowed)
    }

    /// Checks whether this tag is a known attribute tag in KMS.
    #[must_use]
    pub const fn is_supported_attribute(self) -> bool {
        matches!(
            self,
            Self::ActivationDate
                | Self::AlternativeName
                | Self::AlwaysSensitive
                | Self::ApplicationSpecificInformation
                | Self::ArchiveDate
                | Self::AttributeIndex
                | Self::CertificateAttributes
                | Self::CertificateType
                | Self::CertificateLength
                | Self::Comment
                | Self::CompromiseDate
                | Self::CompromiseOccurrenceDate
                | Self::ContactInformation
                | Self::CriticalityIndicator
                | Self::CryptographicAlgorithm
                | Self::CryptographicDomainParameters
                | Self::CryptographicLength
                | Self::CryptographicParameters
                | Self::CryptographicUsageMask
                | Self::DeactivationDate
                | Self::Description
                | Self::DestroyDate
                | Self::Digest
                | Self::DigitalSignatureAlgorithm
                | Self::Extractable
                | Self::Fresh
                | Self::InitialDate
                | Self::KeyFormatType
                | Self::KeyValueLocation
                | Self::KeyValuePresent
                | Self::LastChangeDate
                | Self::LeaseTime
                | Self::Link
                | Self::LinkType
                | Self::Name
                | Self::NeverExtractable
                | Self::NISTKeyType
                | Self::ObjectGroup
                | Self::ObjectGroupMember
                | Self::ObjectType
                | Self::OpaqueDataType
                | Self::OriginalCreationDate
                | Self::PKCS12FriendlyName
                | Self::ProcessStartDate
                | Self::ProtectStopDate
                | Self::ProtectionLevel
                | Self::ProtectionPeriod
                | Self::ProtectionStorageMasks
                | Self::QuantumSafe
                | Self::RandomNumberGenerator
                | Self::RevocationReason
                | Self::RotateAutomatic
                | Self::RotateDate
                | Self::RotateGeneration
                | Self::RotateInterval
                | Self::RotateLatest
                | Self::RotateName
                | Self::RotateOffset
                | Self::Sensitive
                | Self::ShortUniqueIdentifier
                | Self::State
                | Self::UniqueIdentifier
                | Self::UsageLimits
                | Self::X509CertificateIdentifier
                | Self::X509CertificateIssuer
                | Self::X509CertificateSubject
        )
    }
}

impl Attribute {
    /// Returns the edit policy for this attribute under the given operation.
    #[must_use]
    pub fn edit_policy(&self, operation: KmipOperation) -> Option<AttributeEditPolicy> {
        match self {
            Self::VendorAttribute(_) => match operation {
                KmipOperation::AddAttribute
                | KmipOperation::SetAttribute
                | KmipOperation::ModifyAttribute
                | KmipOperation::DeleteAttribute => Some(AttributeEditPolicy::Allowed),
                _ => None,
            },
            _ => self.tag().and_then(|tag| tag.edit_policy(operation)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_edit_operations_return_none() {
        assert_eq!(Tag::Comment.edit_policy(KmipOperation::Get), None);
        assert_eq!(Tag::Comment.edit_policy(KmipOperation::Create), None);
        assert_eq!(Tag::Comment.edit_policy(KmipOperation::Destroy), None);
    }

    #[test]
    fn test_non_attribute_tags_return_none() {
        assert_eq!(
            Tag::BatchCount.edit_policy(KmipOperation::SetAttribute),
            None
        );
        assert_eq!(
            Tag::RequestPayload.edit_policy(KmipOperation::AddAttribute),
            None
        );
    }

    #[test]
    fn test_server_managed_for_all_edit_operations() {
        let always_server_managed = [
            Tag::AlwaysSensitive,
            Tag::NeverExtractable,
            Tag::RotateGeneration,
            Tag::RotateDate,
            Tag::RotateLatest,
        ];

        let ops = [
            KmipOperation::AddAttribute,
            KmipOperation::SetAttribute,
            KmipOperation::ModifyAttribute,
            KmipOperation::DeleteAttribute,
        ];

        for tag in always_server_managed {
            for op in ops {
                assert_eq!(
                    tag.edit_policy(op),
                    Some(AttributeEditPolicy::ServerManaged),
                    "{tag:?} with {op:?} should be ServerManaged"
                );
            }
        }
    }

    #[test]
    fn test_modify_and_delete_server_managed_tags() {
        let tags = [
            Tag::UniqueIdentifier,
            Tag::ObjectType,
            Tag::CryptographicLength,
            Tag::CertificateLength,
            Tag::Digest,
            Tag::InitialDate,
            Tag::Fresh,
            Tag::LastChangeDate,
            Tag::OriginalCreationDate,
        ];

        for tag in tags {
            assert_eq!(
                tag.edit_policy(KmipOperation::AddAttribute),
                Some(AttributeEditPolicy::Allowed),
                "{tag:?} with AddAttribute should be Allowed"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::SetAttribute),
                Some(AttributeEditPolicy::Allowed),
                "{tag:?} with SetAttribute should be Allowed"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::ModifyAttribute),
                Some(AttributeEditPolicy::ServerManaged),
                "{tag:?} with ModifyAttribute should be ServerManaged"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::DeleteAttribute),
                Some(AttributeEditPolicy::ServerManaged),
                "{tag:?} with DeleteAttribute should be ServerManaged"
            );
        }
    }

    #[test]
    fn test_state_policy() {
        assert_eq!(
            Tag::State.edit_policy(KmipOperation::AddAttribute),
            Some(AttributeEditPolicy::Allowed)
        );
        assert_eq!(
            Tag::State.edit_policy(KmipOperation::SetAttribute),
            Some(AttributeEditPolicy::ServerManaged)
        );
        assert_eq!(
            Tag::State.edit_policy(KmipOperation::ModifyAttribute),
            Some(AttributeEditPolicy::ServerManaged)
        );
        assert_eq!(
            Tag::State.edit_policy(KmipOperation::DeleteAttribute),
            Some(AttributeEditPolicy::ServerManaged)
        );
    }

    #[test]
    fn test_rotate_automatic_policy() {
        assert_eq!(
            Tag::RotateAutomatic.edit_policy(KmipOperation::AddAttribute),
            Some(AttributeEditPolicy::ServerManaged)
        );
        assert_eq!(
            Tag::RotateAutomatic.edit_policy(KmipOperation::SetAttribute),
            Some(AttributeEditPolicy::Allowed)
        );
        assert_eq!(
            Tag::RotateAutomatic.edit_policy(KmipOperation::ModifyAttribute),
            Some(AttributeEditPolicy::Allowed)
        );
        assert_eq!(
            Tag::RotateAutomatic.edit_policy(KmipOperation::DeleteAttribute),
            Some(AttributeEditPolicy::ServerManaged)
        );
    }

    #[test]
    fn test_sensitive_and_extractable_policy() {
        for tag in [Tag::Sensitive, Tag::Extractable] {
            assert_eq!(
                tag.edit_policy(KmipOperation::AddAttribute),
                Some(AttributeEditPolicy::RequiresGrant),
                "{tag:?} with AddAttribute should be RequiresGrant"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::SetAttribute),
                Some(AttributeEditPolicy::RequiresGrant),
                "{tag:?} with SetAttribute should be RequiresGrant"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::ModifyAttribute),
                Some(AttributeEditPolicy::RequiresGrant),
                "{tag:?} with ModifyAttribute should be RequiresGrant"
            );
            assert_eq!(
                tag.edit_policy(KmipOperation::DeleteAttribute),
                Some(AttributeEditPolicy::ServerManaged),
                "{tag:?} with DeleteAttribute should be ServerManaged"
            );
        }
    }

    #[test]
    fn test_allowed_attributes_across_all_operations() {
        let allowed_tags = [
            Tag::ActivationDate,
            Tag::AlternativeName,
            Tag::ApplicationSpecificInformation,
            Tag::ArchiveDate,
            Tag::Comment,
            Tag::Description,
            Tag::Link,
            Tag::LinkType,
            Tag::Name,
            Tag::ObjectGroup,
        ];

        let ops = [
            KmipOperation::AddAttribute,
            KmipOperation::SetAttribute,
            KmipOperation::ModifyAttribute,
            KmipOperation::DeleteAttribute,
        ];

        for tag in allowed_tags {
            for op in ops {
                assert_eq!(
                    tag.edit_policy(op),
                    Some(AttributeEditPolicy::Allowed),
                    "{tag:?} with {op:?} should be Allowed"
                );
            }
        }
    }
}
