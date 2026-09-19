pub(crate) mod audit;
pub(crate) mod certificate;
#[cfg(feature = "non-fips")]
pub(crate) mod cover_crypt;
pub(crate) mod kms;
pub(crate) mod operations;
pub(crate) mod otel_metrics;
pub(crate) mod retrieve_object_utils;
pub(crate) mod rng;
mod uid_utils;
pub(crate) use uid_utils::ObjectHandle;
pub(crate) mod wrapping;

pub use kms::KMS;
pub use otel_metrics::OtelMetrics;

use crate::{error::KmsError, result::KResult};

/// Reject an operation restricted to the leader region of a multi-region active-active
/// deployment (see [`crate::config::RegionRole`]). No-op for the default single-region
/// `Leader` role.
pub(crate) fn require_leader_region(kms: &KMS, action: &str) -> KResult<()> {
    if kms.params.region_role == crate::config::RegionRole::Follower {
        return Err(KmsError::InvalidRequest(format!(
            "{action} is only permitted on the leader region of a multi-region deployment; \
             this node is configured with `region_role = follower`. Retry the request against \
             the leader region."
        )));
    }
    Ok(())
}
