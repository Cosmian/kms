use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::{
        kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
        ttlv::{KmipFlavor, TTLV, from_ttlv, to_ttlv, xml::KmipXmlDoc},
    },
};
use cosmian_logger::{info, log_init, warn};
use test_kms_server::start_default_test_kms_server;

use crate::tests::xml::{
    compare::compare_response_messages,
    deviations::{KNOWN_FAILING, REDIS_UNSUPPORTED, take_unused_deviations},
    expected_response::{
        capture_generated_uids, capture_real_uids_from_response, prepare_expected_response,
    },
    request::PrepareRequest,
};

/// Vector families run by dedicated tests in `kmip.rs`: TL and SASED are cross-vector
/// scenarios, PKCS11 needs an HSM.
const DELEGATED_PREFIXES: [&str; 3] = ["TL-", "SASED-", "PKCS11-"];

/// File stem of a vector path.
pub(crate) fn vector_stem(path: &Path) -> &str {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_else(|| panic!("vector path without UTF-8 file stem: {}", path.display()))
}

/// Sorted `*.xml` files of a vector directory.
pub(crate) fn vector_paths(dir: &str) -> Vec<PathBuf> {
    let dir_path = PathBuf::from(dir);
    assert!(
        dir_path.is_dir(),
        "XML vector directory not found: {}",
        dir_path.display()
    );
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir_path)
        .unwrap_or_else(|e| panic!("cannot read directory {}: {e}", dir_path.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("cannot read entry of {}: {e}", dir_path.display()))
                .path()
        })
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("xml"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "No XML files found in {}",
        dir_path.display()
    );
    entries
}

/// Run every XML vector of a directory (sorted) against the shared test server.
///
/// `DELEGATED_PREFIXES` vectors are skipped here: their dedicated tests in `kmip.rs` select
/// them from the same directories with `delegated_vector_paths`.
pub(crate) async fn run_all_xml_vectors_in_dir(dir: &str) {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let paths = vector_paths(dir);
    let run = paths.iter().map(PathBuf::as_path).filter(|path| {
        let stem = vector_stem(path);
        !DELEGATED_PREFIXES.iter().any(|p| stem.starts_with(p))
    });
    run_vectors_checked(None, &client, run).await;
}

/// The mandatory and optional vector directories of a version (`"v2.1"`).
pub(crate) fn vector_dirs(version: &str) -> [String; 2] {
    ["mandatory", "optional"].map(|kind| format!("../../../kmip/{version}/XML/{kind}"))
}

/// Vectors of every served version (all but 3.0) whose stem starts with `prefix`, one of
/// `DELEGATED_PREFIXES`.
pub(crate) fn delegated_vector_paths(prefix: &str) -> Vec<PathBuf> {
    assert!(
        DELEGATED_PREFIXES.contains(&prefix),
        "{prefix} is not delegated"
    );
    ["v1.0", "v1.3", "v1.4", "v2.0", "v2.1"]
        .iter()
        .flat_map(|v| vector_dirs(v))
        .flat_map(|dir| vector_paths(&dir))
        .filter(|path| vector_stem(path).starts_with(prefix))
        .collect()
}

/// Run vectors in order, honouring `KNOWN_FAILING`: a listed vector must fail with its listed
/// error, any other must pass and use every `DEVIATIONS` row it has. Every vector runs; all
/// violations are reported together in one panic.
///
/// `scenario` names vectors that form one scenario (TL: TL-M-2 creates what TL-M-3 locates):
/// they share UID placeholders. `None` gives each vector its own placeholders. Objects the
/// server generated stay known across the vectors of one call.
pub(crate) async fn run_vectors_checked(
    scenario: Option<&str>,
    client: &KmsClient,
    paths: impl IntoIterator<Item = &Path>,
) {
    let mut failures = Vec::new();
    let mut total = 0_usize;
    let mut skipped = 0_usize;
    let mut generated_uids = HashSet::new();
    let mut scenario_uids = HashMap::new();
    for path in paths {
        let stem = vector_stem(path);
        if on_redis_findex() {
            if let Some((_, reason)) = REDIS_UNSUPPORTED.iter().find(|(p, _)| stem.starts_with(p)) {
                warn!("{stem}: skipped on Redis-findex ({reason})");
                skipped += 1;
                continue;
            }
        }
        total += 1;
        drop(take_unused_deviations(stem));
        let mut own_uids = HashMap::new();
        let result = try_run_single_xml_vector_on_client(
            scenario.unwrap_or(stem),
            client,
            path,
            if scenario.is_some() {
                &mut scenario_uids
            } else {
                &mut own_uids
            },
            &mut generated_uids,
        )
        .await;
        match (KNOWN_FAILING.iter().find(|(s, ..)| *s == stem), result) {
            (Some((_, expected, reason)), Err(e)) => {
                if e.contains(expected) {
                    warn!("{stem}: known failing ({reason})");
                } else {
                    failures.push(format!(
                        "{stem}: KNOWN_FAILING expects an error containing {expected:?}, got: {e}"
                    ));
                }
            }
            (Some(_), Ok(())) => {
                failures.push(format!(
                    "{stem}: listed in KNOWN_FAILING but now passes; remove it"
                ));
            }
            (None, Err(e)) => failures.push(e),
            (None, Ok(())) => {
                let unused = take_unused_deviations(stem);
                if unused.is_empty() {
                    info!("{stem}: passed");
                } else {
                    failures.push(format!(
                        "{stem}: passes without its DEVIATIONS rows {unused:?}; remove them"
                    ));
                }
            }
        }
    }
    assert!(total + skipped > 0, "no vectors to run");
    assert!(
        failures.is_empty(),
        "{} of {total} vector(s) failed:\n\n{}",
        failures.len(),
        failures.join("\n\n────────\n\n")
    );
}

/// Whether the shared test server runs on the Redis-findex backend (`KMS_TEST_DB`).
fn on_redis_findex() -> bool {
    matches!(
        std::env::var("KMS_TEST_DB").as_deref(),
        Ok("redis-findex" | "redis")
    )
}

/// Message encoding used to send a vector's requests to `/kmip`.
#[derive(Clone, Copy)]
enum Transport {
    Binary,
    Json,
}

/// Send a request to `/kmip` with the given encoding; binary KMIP 1.x requests use the
/// 1.x wire flavor.
async fn post_message(
    client: &KmsClient,
    request: &RequestMessage,
    transport: Transport,
) -> Result<ResponseMessage, String> {
    let ttlv = to_ttlv(request).map_err(|e| format!("TTLV encoding failed: {e}"))?;
    let flavor = if request
        .request_header
        .protocol_version
        .protocol_version_major
        == 1
    {
        KmipFlavor::Kmip1
    } else {
        KmipFlavor::Kmip2
    };
    let (bytes, content_type) = match transport {
        Transport::Binary => (
            ttlv.to_bytes(flavor)
                .map_err(|e| format!("binary encoding failed: {e}"))?,
            "application/octet-stream",
        ),
        Transport::Json => (
            serde_json::to_vec(&ttlv).map_err(|e| format!("JSON encoding failed: {e}"))?,
            "application/json",
        ),
    };
    let url = format!("{}/kmip", client.client.server_url);
    let response = client
        .client
        .post_bytes(&url, bytes, content_type)
        .await
        .map_err(|e| e.to_string())?;
    if !response.status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            response.status,
            response.text().unwrap_or_default()
        ));
    }
    let ttlv = match transport {
        Transport::Binary => TTLV::from_bytes(response.bytes(), flavor)
            .map_err(|e| format!("binary decoding failed: {e}"))?,
        Transport::Json => serde_json::from_slice::<TTLV>(response.bytes())
            .map_err(|e| format!("JSON decoding failed: {e}"))?,
    };
    from_ttlv(ttlv).map_err(|e| format!("response decoding failed: {e}"))
}

/// Run a vector and return the first mismatch as an error. `uid_map` holds the UID
/// placeholders (updated in place); `generated_uids` collects the objects the server generates.
async fn try_run_single_xml_vector_on_client(
    test_name: &str,
    client: &KmsClient,
    path: &Path,
    uid_map: &mut HashMap<usize, String>,
    generated_uids: &mut HashSet<String>,
) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("XML vector file not found: {}", path.display()));
    }
    let doc = KmipXmlDoc::new_with_file(path)
        .map_err(|e| format!("parse xml vector {}: {e}", path.display()))?;
    if doc.requests.len() != doc.responses.len() {
        return Err(format!(
            "{}: mismatched request/response count ({} vs {})",
            path.display(),
            doc.requests.len(),
            doc.responses.len()
        ));
    }
    let mut prepare_req = PrepareRequest::with_empty_request(test_name);
    prepare_req.uid_placeholder_map = std::mem::take(uid_map);
    let result = run_requests(
        test_name,
        client,
        path,
        &mut prepare_req,
        doc.requests.into_iter().zip(doc.responses),
        generated_uids,
    )
    .await;
    *uid_map = prepare_req.uid_placeholder_map;
    result
}

async fn run_requests(
    test_name: &str,
    client: &KmsClient,
    path: &Path,
    prepare_req: &mut PrepareRequest,
    exchanges: impl Iterator<Item = (RequestMessage, ResponseMessage)>,
    generated_uids: &mut HashSet<String>,
) -> Result<(), String> {
    let stem = vector_stem(path);
    let transport = if stem.starts_with("MSGENC-JSON-") {
        Transport::Json
    } else {
        Transport::Binary
    };
    let mut pending_encrypt_aad: Option<Vec<u8>>;
    for (idx, (request, mut expected_resp)) in exchanges.enumerate() {
        let bi_len = request.batch_item.len();
        if bi_len == 0 {
            return Err(format!("{}: request with zero batch items", path.display()));
        }
        if usize::try_from(request.request_header.batch_count).ok() != Some(bi_len) {
            return Err(format!(
                "{}: request batch_count mismatch (header={} actual={})",
                path.display(),
                request.request_header.batch_count,
                bi_len
            ));
        }

        prepare_req.request = request;
        pending_encrypt_aad = None;
        prepare_req.capture_encrypt_request_aad(&mut pending_encrypt_aad);
        prepare_req.expected_response_is_missing_iv_error(&expected_resp);
        let (injected_sig, injected_mac) = prepare_req.prepare_request();

        let resp = post_message(client, &prepare_req.request, transport)
            .await
            .map_err(|e| {
                format!(
                    "{}: send error at request[{idx}]: {e}. Request: \n{}",
                    path.display(),
                    prepare_req.request
                )
            })?;

        // Locate expectations name objects known before this response, never its own results.
        let prior_uids = prepare_req.uid_placeholder_map.clone();
        capture_real_uids_from_response(test_name, &resp, &mut prepare_req.uid_placeholder_map);
        capture_generated_uids(&resp, generated_uids);
        prepare_req.update_cached_artifacts(&resp, &mut pending_encrypt_aad);
        prepare_expected_response(
            test_name,
            &mut expected_resp,
            &resp,
            &prepare_req.uid_placeholder_map,
            &prior_uids,
        );

        if injected_sig {
            prepare_req.last_signature_from_sign = None;
        }
        if injected_mac {
            prepare_req.last_mac_from_mac = None;
        }

        compare_response_messages(stem, idx, generated_uids, &expected_resp, &resp).map_err(|e| {
            format!(
                "{}: response mismatch at request[{idx}]\n\nRequest: {}\n\nExpected: {expected_resp}\n\nActual: {resp}\n\nError: {e}",
                path.display(),
                prepare_req.request
            )
        })?;
    }
    Ok(())
}
