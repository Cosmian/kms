use crate::{RbacResult, input::RbacInput};

/// Trait for RBAC policy engines.
///
/// Implementations evaluate an authorization request (as [`RbacInput`]) against
/// loaded Rego policies and return whether the action is allowed.
pub trait RbacEngine: Send + Sync {
    /// Evaluate the RBAC policy for the given input.
    ///
    /// Returns `Ok(true)` if the policy allows the action,
    /// `Ok(false)` if the policy denies it, or `Err` on evaluation error.
    fn evaluate(&self, input: &RbacInput) -> RbacResult<bool>;
}
