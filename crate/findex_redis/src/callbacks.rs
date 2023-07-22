use std::collections::HashSet;

use cosmian_findex::Location;

use crate::FindexError;

pub trait RemovedLocationsFinder {
    async fn find_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError>;
}
