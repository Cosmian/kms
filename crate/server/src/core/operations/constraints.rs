//! KMIP 2.1 Set Constraints (§6.1.52), Get Constraints (§6.1.22) and their enforcement.
//!
//! The constraint set is server-wide and held in memory: it is lost on restart and not shared
//! between server instances. Set Constraints replaces it; a request without Constraints (as in
//! the OASIS test case TC-MD-24-21) or with an empty one clears it. Get Constraints returns it
//! exactly as set, order preserved.
//!
//! Validation: a Constraint's Object Types must be types this server manages (else
//! `Invalid Object Type`); an Object Types or Object Groups structure must not be empty (else
//! `Invalid Field`).
//!
//! Authorization: [`check_role_permission`](super::dispatch::check_role_permission) applies.
//! When roles are configured, Set Constraints is reserved to Crypto Officers (Operators fail
//! closed) while Get Constraints is open to all; with no roles configured, any authenticated
//! user may set them.
//!
//! Enforcement: while the set is not empty, every Managed Object stored by Create, Create Key
//! Pair (both keys), Register, Import, Derive Key, Re-key and Re-key Key Pair (including the
//! automatic rotation scheduler, which runs them), Re-certify, Certify (the certificate and the
//! key pair it generates), Create Split Key (each share) and Join Split Key must satisfy at
//! least one Constraint, else the operation fails with `Constraint Violation` before anything
//! is stored. An object satisfies a Constraint when:
//! - its Object Type is listed in the Constraint's Object Types (when present),
//! - its Object Group attribute is listed in the Constraint's Object Groups (when present),
//! - every attribute value of the Constraint's Attributes is one of the object's values.
//!
//! Not covered: attribute changes on existing objects (Add/Modify/Set/Delete Attribute), and
//! the objects the server creates for itself at startup or in tests outside these operations.

use std::sync::{PoisonError, RwLock};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            kmip_attributes::{Attribute, Attributes},
            kmip_objects::ObjectType,
            kmip_operations::{
                Constraint, Constraints, GetConstraintsResponse, SetConstraints,
                SetConstraintsResponse,
            },
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::info;

use super::query::SUPPORTED_QUERY_OBJECT_TYPES;
use crate::{core::KMS, error::KmsError, result::KResult};

/// A constraint as set, with its attributes flattened once for matching.
struct Rule {
    constraint: Constraint,
    attributes: Vec<Attribute>,
}

impl Rule {
    fn is_satisfied_by(
        &self,
        object_type: ObjectType,
        attributes: &Attributes,
        object_attributes: &[Attribute],
    ) -> bool {
        let c = &self.constraint;
        c.object_types
            .as_ref()
            .is_none_or(|types| types.object_type.contains(&object_type))
            && c.object_groups.as_ref().is_none_or(|groups| {
                attributes
                    .object_group
                    .as_ref()
                    .is_some_and(|group| groups.object_group.contains(group))
            })
            && self
                .attributes
                .iter()
                .all(|a| object_attributes.contains(a))
    }
}

/// The server-wide constraint set.
#[derive(Default)]
pub(crate) struct ConstraintStore(RwLock<Vec<Rule>>);

impl ConstraintStore {
    /// Fails with `Constraint Violation` unless an object of `object_type` with `attributes`
    /// satisfies at least one constraint (always succeeds when none is set).
    pub(crate) fn check(&self, object_type: ObjectType, attributes: &Attributes) -> KResult<()> {
        // The set is replaced in one assignment: it is consistent even if a writer panicked.
        let rules = self.0.read().unwrap_or_else(PoisonError::into_inner);
        if rules.is_empty() {
            return Ok(());
        }
        let object_attributes: Vec<Attribute> = attributes.clone().into();
        if rules
            .iter()
            .any(|rule| rule.is_satisfied_by(object_type, attributes, &object_attributes))
        {
            return Ok(());
        }
        Err(KmsError::Kmip21Error(
            ErrorReason::Constraint_Violation,
            format!("a {object_type} with these attributes violates the server constraints"),
        ))
    }

    /// [`Self::check`] for every object a list of database operations creates or replaces.
    pub(crate) fn check_new_objects(&self, operations: &[AtomicOperation]) -> KResult<()> {
        for operation in operations {
            if let AtomicOperation::Create((_, _, object, attributes, _))
            | AtomicOperation::Upsert((_, object, attributes, _, _)) = operation
            {
                self.check(object.object_type(), attributes)?;
            }
        }
        Ok(())
    }
}

fn validate(constraint: &Constraint) -> KResult<()> {
    if let Some(types) = &constraint.object_types {
        if types.object_type.is_empty() {
            return Err(invalid_field("an Object Types structure must not be empty"));
        }
        if let Some(t) = types
            .object_type
            .iter()
            .find(|t| !SUPPORTED_QUERY_OBJECT_TYPES.contains(t))
        {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                format!("Set Constraints: object type {t} is not supported by this server"),
            ));
        }
    }
    if constraint
        .object_groups
        .as_ref()
        .is_some_and(|groups| groups.object_group.is_empty())
    {
        return Err(invalid_field(
            "an Object Groups structure must not be empty",
        ));
    }
    Ok(())
}

fn invalid_field(message: &str) -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Invalid_Field,
        format!("Set Constraints: {message}"),
    )
}

/// Executes Set Constraints: replaces the server constraint set (cleared when absent).
pub(crate) fn set_constraints(
    kms: &KMS,
    request: SetConstraints,
    user: &str,
) -> KResult<SetConstraintsResponse> {
    let constraints = request.constraints.unwrap_or_default().constraint;
    let rules = constraints
        .into_iter()
        .map(|constraint| {
            validate(&constraint)?;
            let attributes = constraint
                .attributes
                .clone()
                .map(Vec::from)
                .unwrap_or_default();
            Ok(Rule {
                constraint,
                attributes,
            })
        })
        .collect::<KResult<Vec<_>>>()?;
    info!(
        "KMIP Set Constraints from user {user:?}: {} constraint(s)",
        rules.len()
    );
    *kms.constraints
        .0
        .write()
        .unwrap_or_else(PoisonError::into_inner) = rules;
    Ok(SetConstraintsResponse)
}

/// Executes Get Constraints: returns the server constraint set as set.
pub(crate) fn get_constraints(kms: &KMS) -> GetConstraintsResponse {
    let rules = kms
        .constraints
        .0
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    GetConstraintsResponse {
        constraints: Constraints {
            constraint: rules.iter().map(|rule| rule.constraint.clone()).collect(),
        },
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "tests assert inside fallible setup"
)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_operations::{Create, ObjectGroups, ObjectTypes},
        kmip_types::CryptographicAlgorithm,
    };

    use super::*;
    use crate::{middlewares::UserId, tests::test_utils::test_kms};

    fn aes(length: i32, group: Option<&str>) -> Attributes {
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(length),
            object_group: group.map(str::to_owned),
            ..Attributes::default()
        }
    }

    /// The two constraints of TC-MD-24-21.
    fn md_24_constraints() -> Constraints {
        Constraints {
            constraint: vec![
                Constraint {
                    object_types: Some(ObjectTypes {
                        object_type: vec![ObjectType::SymmetricKey],
                    }),
                    object_groups: Some(ObjectGroups {
                        object_group: vec!["Group1".to_owned()],
                    }),
                    attributes: Some(aes(256, None)),
                },
                Constraint {
                    object_types: Some(ObjectTypes {
                        object_type: vec![ObjectType::SymmetricKey],
                    }),
                    object_groups: None,
                    attributes: Some(aes(192, None)),
                },
            ],
        }
    }

    fn reason(result: KResult<impl Sized>) -> Option<ErrorReason> {
        match result.err()? {
            KmsError::Kmip21Error(r, _) => Some(r),
            _ => None,
        }
    }

    #[tokio::test]
    async fn matching_types_groups_and_attributes() -> KResult<()> {
        let kms = test_kms().await?;
        let store = &kms.constraints;
        // No constraint: no restriction.
        store.check(ObjectType::PrivateKey, &Attributes::default())?;

        set_constraints(
            &kms,
            SetConstraints {
                constraints: Some(md_24_constraints()),
            },
            "admin",
        )?;
        store.check(ObjectType::SymmetricKey, &aes(256, Some("Group1")))?;
        store.check(ObjectType::SymmetricKey, &aes(192, None))?;
        for (object_type, attributes) in [
            // group missing or different
            (ObjectType::SymmetricKey, aes(256, None)),
            (ObjectType::SymmetricKey, aes(256, Some("Group2"))),
            // attribute differs
            (ObjectType::SymmetricKey, aes(128, Some("Group1"))),
            // type not listed
            (ObjectType::SecretData, aes(192, None)),
        ] {
            assert_eq!(
                reason(store.check(object_type, &attributes)),
                Some(ErrorReason::Constraint_Violation)
            );
        }
        assert_eq!(get_constraints(&kms).constraints, md_24_constraints());

        // Absent Constraints clear the set.
        set_constraints(&kms, SetConstraints::default(), "admin")?;
        assert_eq!(get_constraints(&kms).constraints, Constraints::default());
        store.check(ObjectType::SecretData, &Attributes::default())?;
        Ok(())
    }

    #[tokio::test]
    async fn invalid_constraints_are_rejected() -> KResult<()> {
        let kms = test_kms().await?;
        let set = |constraint: Constraint| {
            set_constraints(
                &kms,
                SetConstraints {
                    constraints: Some(Constraints {
                        constraint: vec![constraint],
                    }),
                },
                "admin",
            )
        };
        assert_eq!(
            reason(set(Constraint {
                object_types: Some(ObjectTypes {
                    object_type: vec![ObjectType::CertificateRequest],
                }),
                ..Constraint::default()
            })),
            Some(ErrorReason::Invalid_Object_Type)
        );
        assert_eq!(
            reason(set(Constraint {
                object_groups: Some(ObjectGroups::default()),
                ..Constraint::default()
            })),
            Some(ErrorReason::Invalid_Field)
        );
        // A rejected request leaves the set unchanged.
        assert_eq!(get_constraints(&kms).constraints, Constraints::default());
        Ok(())
    }

    #[tokio::test]
    async fn create_violating_the_constraints_fails() -> KResult<()> {
        let kms = test_kms().await?;
        let user = UserId::from("constraints@example.com");
        set_constraints(
            &kms,
            SetConstraints {
                constraints: Some(md_24_constraints()),
            },
            "admin",
        )?;
        let create = |attributes: Attributes| Create {
            object_type: ObjectType::SymmetricKey,
            attributes,
            protection_storage_masks: None,
        };
        assert_eq!(
            reason(kms.create(create(aes(128, None)), &user).await),
            Some(ErrorReason::Constraint_Violation)
        );
        kms.create(create(aes(192, None)), &user).await?;
        kms.create(create(aes(256, Some("Group1"))), &user).await?;
        Ok(())
    }
}
