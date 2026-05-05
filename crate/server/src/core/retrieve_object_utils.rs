use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::KmipOperation,
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};

use crate::{core::KMS, error::KmsError, result::KResult};

// TODO This function should probably not be a free-standing function KMS side,
// and should be refactored as part of the Database,

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// When tags are provided, the function will return the first object
/// that matches the tags and the operation type.
///
/// This function assumes that if the user can `Get` the object,
/// it can then also perform any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "uid_or_tags: {uid_or_tags:?}, user: {user}, \
         operation_type: {operation_type:?}"
    );

    for owm in kms.database.retrieve_objects(uid_or_tags).await?.values() {
        trace!("Checking key with ID: {}", owm.id());
        let state = owm.state();
        // Allow retrieval based on state and operation semantics.
        // Rules:
        // - Active / PreActive: always retrievable.
        // - Compromised: permitted for Get / Export / GetAttributes (profiling vectors inspect attrs post-revoke).
        // - Destroyed / Destroyed_Compromised: ONLY permit GetAttributes so clients can read lifecycle state.
        let state_allows = match state {
            State::Active | State::PreActive | State::Deactivated => true,
            State::Compromised => matches!(
                operation_type,
                KmipOperation::Get | KmipOperation::Export | KmipOperation::GetAttributes
            ),
            State::Destroyed | State::Destroyed_Compromised => {
                // KMIP profiles expect Get on a destroyed object to return OperationFailed / ObjectDestroyed
                // rather than ObjectNotFound. We therefore allow retrieval for Get so the operation layer
                // can emit the correct Object_Destroyed error (BL-M-8-21 vector). Still restrict other
                // operations besides GetAttributes and Get.
                matches!(
                    operation_type,
                    KmipOperation::Get | KmipOperation::GetAttributes
                )
            }
        };
        if !state_allows {
            trace!(
                "state_allows: {state_allows}: state: {state}, operation_type: {operation_type}"
            );
            continue;
        }

        if user_has_permission(user, Some(owm), &operation_type, kms).await? {
            trace!(
                "User {user} has permission for operation {operation_type:?} on object {}",
                owm.id()
            );
            let mut owm = owm.to_owned();
            // Compute effective state with lifecycle precedence:
            // - If the DB marks the object as Destroyed / Destroyed_Compromised / Compromised / Deactivated,
            //   NEVER override it with attribute-level values.
            // - Otherwise (Active/PreActive), prefer attribute PreActive when present to satisfy
            //   profile vectors that keep objects PreActive until explicit Activate.
            let attr_state = owm.attributes().state;
            let effective_state = match state {
                State::Destroyed
                | State::Destroyed_Compromised
                | State::Compromised
                | State::Deactivated
                | State::Active => state, // never downgrade Active to PreActive
                State::PreActive => attr_state.unwrap_or(State::PreActive),
            };
            // Synchronize both external attributes and embedded object attributes to effective state
            owm.attributes_mut().state = Some(effective_state);
            if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                attributes.state = Some(effective_state);
            }

            // KMIP 2.1 Auto-activation: Automatically activate PreActive objects when activation_date has passed
            // This ensures the database state stays synchronized with the object's actual lifecycle state
            if effective_state == State::PreActive {
                // Check if activation_date is set and has passed
                let activation_date = owm.attributes().activation_date.or_else(|| {
                    // Fallback to object's attributes if not in metadata
                    owm.object()
                        .attributes()
                        .ok()
                        .and_then(|attrs| attrs.activation_date)
                });

                if let Some(activation_date) = activation_date {
                    let now = time_normalize()?;
                    if activation_date <= now {
                        // Activation date has passed, automatically transition to Active
                        trace!(
                            "Auto-activating object {} (activation_date {} <= now {})",
                            owm.id(),
                            activation_date,
                            now
                        );

                        // Update state in both the object attributes and metadata
                        owm.attributes_mut().state = Some(State::Active);
                        if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                            attributes.state = Some(State::Active);
                        }

                        // Persist the state change to database
                        // Note: We do this synchronously to ensure consistency, but log errors
                        // rather than failing the retrieval if the update fails
                        if let Err(e) = kms.database.update_state(owm.id(), State::Active).await {
                            warn!(
                                "Failed to persist auto-activation of object {}: {}",
                                owm.id(),
                                e
                            );
                        }
                    }
                }
            }

            // Automatic object unwrapping (if object type is not filtered)
            // Skip unwrapping for destroyed objects as they have empty key material
            if let Some(defaults) = &kms.params.default_unwrap_types {
                if defaults.contains(&owm.object().object_type())
                    && state != State::Destroyed
                    && state != State::Destroyed_Compromised
                {
                    let unwrapped_object = kms.get_unwrapped(owm.id(), owm.object(), user).await?;
                    owm.set_object(unwrapped_object);
                }
            }

            return Ok(owm);
        }
        trace!(
            "User {user} does not have permission for operation {operation_type:?} on object {}",
            owm.id()
        );
    }

    Err(KmsError::Kmip21Error(
        ErrorReason::Object_Not_Found,
        format!("object not found for identifier {uid_or_tags}"),
    ))
}

/// Check if a user has permission to perform an operation on an object.
///
/// Authorization follows OR logic:
///   1. **Owner check** — the object owner always has full access.
///   2. **RBAC check** — if an RBAC engine is configured, the user's roles
///      are loaded from the database and evaluated against the Rego policy.
///   3. **ACL check** — existing per-object permission grants in the database.
///
/// Access is granted if *any* of the above checks succeed.
///
///  # Arguments
///  * `user` - The user to check the permission for.
///  * `owm` - The object to check the permission on.
///  * `operation_type` - The operation to check the permission for.
///  * `kms` - The KMS instance.
///  # Returns
///  * `Ok(true)` if the user has permission to perform the operation on the object.
///  * `Ok(false)` if the user does not have permission to perform the operation on the object.
pub(crate) async fn user_has_permission(
    user: &str,
    owm: Option<&ObjectWithMetadata>,
    operation_type: &KmipOperation,
    kms: &KMS,
) -> KResult<bool> {
    // 1. Owner always has full access
    let id = match owm {
        Some(object) if user == object.owner() => return Ok(true),
        Some(object) => object.id(),
        None => "*",
    };

    // 2. RBAC check (if engine is configured)
    if let Some(ref rbac_engine) = kms.rbac_engine {
        if rbac_check(rbac_engine.as_ref(), user, owm, operation_type, kms).await? {
            return Ok(true);
        }
    }

    // 3. Legacy ACL check
    let permissions = kms
        .database
        .list_user_operations_on_object(id, user, false)
        .await?;
    Ok(permissions.contains(operation_type) || permissions.contains(&KmipOperation::Get))
}

/// Evaluate the RBAC engine for a given user, object, and operation.
///
/// Builds an [`RbacInput`] following the NIST SP 800-162 attribute model
/// and delegates to the configured RBAC engine (embedded regorus or external OPA).
async fn rbac_check(
    engine: &(dyn cosmian_kms_rbac::RbacEngine + Sync + Send),
    user: &str,
    owm: Option<&ObjectWithMetadata>,
    operation_type: &KmipOperation,
    kms: &KMS,
) -> KResult<bool> {
    use cosmian_kms_rbac::{ActionAttrs, EnvironmentAttrs, RbacInput, ResourceAttrs, SubjectAttrs};

    // Load user roles from the database
    let roles = kms.database.list_user_roles(user).await.unwrap_or_default();
    if roles.is_empty() {
        // No roles assigned — RBAC cannot grant access
        return Ok(false);
    }

    let is_privileged = kms
        .params
        .privileged_users
        .as_ref()
        .is_some_and(|pu| pu.contains(&user.to_owned()));

    let is_owner = owm.is_some_and(|o| o.owner() == user);

    let subject = SubjectAttrs {
        user_id: user.to_owned(),
        roles,
        is_owner,
        is_privileged,
    };

    // Convert KmipOperation to lowercase snake_case for Rego
    let op_name = format!("{operation_type:?}")
        .chars()
        .fold(String::new(), |mut acc, c| {
            if c.is_uppercase() && !acc.is_empty() {
                acc.push('_');
            }
            acc.push(c.to_ascii_lowercase());
            acc
        });

    let action = ActionAttrs { operation: op_name };

    let resource = owm.map_or_else(ResourceAttrs::default, |obj| ResourceAttrs {
        unique_identifier: Some(obj.id().to_owned()),
        object_type: Some(format!("{:?}", obj.object().object_type())),
        state: obj.attributes().state.map(|s| format!("{s:?}")),
        owner: Some(obj.owner().to_owned()),
        sensitive: obj.attributes().sensitive.unwrap_or(false),
        extractable: obj.attributes().extractable.unwrap_or(true),
    });

    let environment = EnvironmentAttrs::default();

    let input = RbacInput {
        subject,
        action,
        resource,
        environment,
    };

    match engine.evaluate(&input) {
        Ok(allowed) => {
            trace!("RBAC decision for user={user}, operation={operation_type:?}: {allowed}");
            Ok(allowed)
        }
        Err(e) => {
            warn!("RBAC evaluation error for user={user}: {e}");
            // On RBAC error, fall through to ACL check
            Ok(false)
        }
    }
}
