use std::sync::Arc;

use actix_web::{
    HttpRequest, get,
    web::{Data, Json},
};
use cosmian_logger::info;
use serde::Serialize;

use crate::{core::KMS, cron::CLUSTER_NODE_TIMEOUT_SECS, result::KResult};

#[derive(Serialize)]
struct ClusterNodeStatus {
    node_id: String,
    version: String,
    last_heartbeat: i64,
    leader: bool,
}

#[derive(Serialize)]
struct ClusterStatus {
    nodes: Vec<ClusterNodeStatus>,
    leader: Option<String>,
}

/// Return live nodes, their latest heartbeat, version, and elected leader.
#[get("/cluster/status")]
pub(crate) async fn get_cluster_status(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<ClusterStatus>> {
    info!("GET /cluster/status {}", kms.get_user(&req));
    let minimum_heartbeat = time::OffsetDateTime::now_utc()
        .unix_timestamp()
        .saturating_sub(CLUSTER_NODE_TIMEOUT_SECS);
    let nodes = kms.database.list_cluster_nodes(minimum_heartbeat).await?;
    let leader = nodes
        .iter()
        .find(|node| node.is_leader)
        .map(|node| node.node_id.clone());
    Ok(Json(ClusterStatus {
        nodes: nodes
            .into_iter()
            .map(|node| ClusterNodeStatus {
                node_id: node.node_id,
                version: node.version,
                last_heartbeat: node.last_heartbeat,
                leader: node.is_leader,
            })
            .collect(),
        leader,
    }))
}
