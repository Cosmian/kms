//! Usage-limit accounting for KMIP cryptographic operations.
//!
//! Keys may carry `UsageLimits` attributes that cap how many bytes / objects /
//! operations they can protect.  This module provides:
//!
//! - [`decrement_usage_limits`] — post-operation persistence.
//!
//! Pre-operation checks (`has_usage_mask`, `enforce_usage_limits`) live on
//! [`ObjectWithMetadata`] directly.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_types::UsageLimitsUnit, cosmian_kms_interfaces::ObjectWithMetadata,
};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Decrement and persist `UsageLimits` after a successful cryptographic operation.
///
/// For `Byte`-based limits, `data_len` bytes are subtracted from the remaining total.
/// For `Object`, `Block`, and `Operation` units, one unit is consumed.
///
/// Persistence (database UPDATE) is skipped when no usage limits are set on the key,
/// avoiding unnecessary row-level lock contention on the hot path.
pub(super) async fn decrement_usage_limits(
    kms: &KMS,
    owm: &mut ObjectWithMetadata,
    op_name: &str,
    data_len: usize,
) -> KResult<()> {
    let mut decremented = false;
    if let Some(ref mut ul) = owm.attributes_mut().usage_limits {
        match ul.usage_limits_unit {
            UsageLimitsUnit::Byte => {
                let consumed = i64::try_from(data_len).unwrap_or(i64::MAX);
                ul.usage_limits_total = (ul.usage_limits_total - consumed).max(0);
                decremented = true;
            }
            UsageLimitsUnit::Object | UsageLimitsUnit::Block | UsageLimitsUnit::Operation => {
                ul.usage_limits_total = (ul.usage_limits_total - 1).max(0);
                decremented = true;
            }
        }
    }
    if decremented {
        let attributes = owm.attributes().clone();
        kms.database
            .update_object(owm.id(), owm.object(), &attributes, None)
            .await
            .map_err(|e| {
                KmsError::ServerError(format!(
                    "{op_name}: failed to persist updated usage limits: {e}"
                ))
            })?;
    }
    Ok(())
}
