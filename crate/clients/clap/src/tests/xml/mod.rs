pub(crate) mod compare;
pub(crate) mod expected_response;
pub(crate) mod kmip;
pub(crate) mod request;
pub(crate) mod runner;
pub(crate) mod versioned;

use crate::tests::xml::runner::run_single_xml_vector_with_server as run_with_server_impl;

/// Run a single XML vector using the shared default test server (single sqlite path).
/// `test_name` is used to namespace UID placeholder keys to avoid cross-test collisions.
pub(crate) async fn run_single_xml_vector(test_name: &str, path: &str) {
    run_with_server_impl(test_name, path).await;
}
