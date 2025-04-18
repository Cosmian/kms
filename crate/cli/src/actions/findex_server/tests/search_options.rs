use std::collections::HashSet;

use cosmian_findex_structs::Value;

#[derive(Clone)]
pub(crate) struct SearchOptions {
    /// The path to the CSV file containing the data to search in
    pub(crate) dataset_path: String,
    /// The keywords to search for
    pub(crate) keywords: Vec<String>,
    pub(crate) expected_results: HashSet<Value>,
}
