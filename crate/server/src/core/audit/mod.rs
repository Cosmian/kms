mod file_sink;
mod recovery;
mod store;
mod writer;

const SIZE_CAP_SENTINEL_OPERATION: &str = "audit:size-cap-reached";

pub(crate) use store::AuditStore;
