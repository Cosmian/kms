use clap::Parser;
use cosmian_findex_cli::reexports::{
    cosmian_findex_client::FindexRestClient, cosmian_findex_structs::Uuids,
};
use uuid::Uuid;

use crate::error::result::CosmianResult;

/// Delete encrypted entries. (Indexes are not deleted)
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DeleteDatasetAction {
    /// Index id
    #[clap(long, short = 'i')]
    pub(crate) index_id: Uuid,

    /// List of UUIDS to delete
    #[clap(long, short = 'u')]
    pub(crate) uuid: Vec<Uuid>,
}

impl DeleteDatasetAction {
    #[allow(clippy::future_not_send, clippy::print_stdout)]
    pub(crate) async fn run(&self, findex_rest_client: FindexRestClient) -> CosmianResult<()> {
        let uuids = Uuids::from(self.uuid.clone());
        findex_rest_client
            .delete_entries(&self.index_id, &uuids)
            .await?;

        println!("Uuids successfully deleted: {uuids}");

        Ok(())
    }
}
