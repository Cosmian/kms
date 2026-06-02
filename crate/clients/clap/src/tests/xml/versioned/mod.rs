//! Version-specific KMIP response handling via traits.
//!
//! This module consolidates the formerly separate `kmip_1_4/` and `kmip_2_1/`
//! sub-modules into a single place. A `VersionedBatchItem` trait provides
//! version-agnostic payload comparison and artifact extraction; concrete
//! implementations exist for `ResponseBatchItem14` and `ResponseBatchItem21`.
//!
//! Designed to be extended for KMIP 3.0+ by adding a new impl block.

mod compare;
mod request;

pub(crate) use compare::compare_versioned_batch_item;
pub(crate) use request::update_cached_artifacts_versioned;
