pub(crate) use unwrap::{
    authorize_stored_unwrap, authorize_unwrap_with, unwrap_object, unwrap_stored_object,
};
pub(crate) use wrap::{ensure_kek_wrapping, wrap_and_cache, wrap_object, wrap_with_local_key};

mod unwrap;
mod wrap;
