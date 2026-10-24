//! OASIS KMIP XML test vectors (`kmip/v*/XML/{mandatory,optional}` and `kmip/website`).
//!
//! Every vector file is accounted for: KMIP 1.0, 1.3, 1.4, 2.0 and 2.1 vectors are run
//! against the server and compared strictly (accepted differences live only in
//! `deviations.rs`); TL and SASED vectors run per version as scenarios (`kmip_xml_tl`,
//! `kmip_xml_sased`), PKCS11 vectors in `kmip_xml_pkcs11` (`SoftHSM2` token); KMIP 3.0 vectors
//! are asserted to be rejected, since the server only serves KMIP 1.x and 2.x. Under
//! `kmip/website`, the published Test Cases notes (cn01) and the draft test cases that no
//! published vector covers run (`kmip_xml_draft_vectors`, newest stage of each, no duplicates);
//! every other file is a mirror or older revision of a run vector, a KMIP 3.0 draft, or not a
//! vector (`kmip_xml_website_vectors_accounted`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use crate::tests::xml::{
    deviations::{DEVIATIONS, KNOWN_FAILING, REASON_DEVIATIONS},
    runner::{
        delegated_vector_paths, run_all_xml_vectors_in_dir, run_vectors_checked, vector_dirs,
        vector_paths, vector_stem,
    },
};

/// Version directories holding OASIS XML vectors.
const VERSIONS: [&str; 6] = ["v1.0", "v1.3", "v1.4", "v2.0", "v2.1", "v3.0"];

// ─── KMIP 1.0 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_0_xml_mandatory() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.0/XML/mandatory").await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_0_xml_optional() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.0/XML/optional").await;
}

// ─── KMIP 1.3 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_3_xml_mandatory() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.3/XML/mandatory").await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_3_xml_optional() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.3/XML/optional").await;
}

// ─── KMIP 1.4 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_4_xml_mandatory() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.4/XML/mandatory").await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_4_xml_optional() {
    run_all_xml_vectors_in_dir("../../../kmip/v1.4/XML/optional").await;
}

// ─── KMIP 2.0 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_0_xml_mandatory() {
    run_all_xml_vectors_in_dir("../../../kmip/v2.0/XML/mandatory").await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_0_xml_optional() {
    run_all_xml_vectors_in_dir("../../../kmip/v2.0/XML/optional").await;
}

// ─── KMIP 2.1 ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_1_xml_mandatory() {
    run_all_xml_vectors_in_dir("../../../kmip/v2.1/XML/mandatory").await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_1_xml_optional() {
    run_all_xml_vectors_in_dir("../../../kmip/v2.1/XML/optional").await;
}

// ─── OASIS website mirror (`kmip/website`) ─────────────────────────────────────

/// Published KMIP Test Cases committee notes (cn01): vectors with no `v*/XML` counterpart.
const WEBSITE_TEST_CASES: [&str; 3] = [
    "../../../kmip/website/testcases/v1.4/cn01/test-cases/kmip-v1.4",
    "../../../kmip/website/kmip-testcases/v2.0/cn01/test-cases/kmip-v2.0",
    "../../../kmip/website/kmip-testcases/v2.1/cn01/test-cases/kmip-v2.1",
];

/// Draft stages of OASIS documents, oldest to newest (committee specification draft, public
/// review draft, committee note draft, ...). When several stages of one test case exist, only
/// the newest is run: the older ones are superseded revisions of the same test, some with
/// expectations the committee later changed.
const DRAFT_STAGES: [&str; 6] = [
    "/cd10/",
    "/csd01/",
    "/csprd01/",
    "/cnd01/",
    "/cnprd01/",
    "/cnd02/",
];

/// Use of a `kmip/website` file (see [`website_classification`]).
const CN01: &str = "run (cn01)";
const MIRROR: &str = "mirror of v*/XML";
const NOT_A_VECTOR: &str = "not a KMIP vector";
const DRAFT_RUN: &str = "run (draft, newest stage of its test case)";
const DRAFT_RUN_ELSEWHERE: &str = "draft of a test case run from v*/XML or cn01";
const DRAFT_SUPERSEDED: &str = "draft superseded by a newer stage";
const DRAFT_DUPLICATE: &str = "draft duplicate of the newest stage";
const DRAFT_V3: &str = "draft of KMIP 3.0 (not served)";
const UNACCOUNTED: &str = "unaccounted";

/// Whitespace- and comment-insensitive content of a vector file.
fn vector_content(path: &Path) -> String {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        rest = rest[start..]
            .find("-->")
            .map_or("", |end| &rest[start + end + 3..]);
    }
    out.push_str(rest);
    out.split_whitespace().collect()
}

/// Every `.xml` file under `dir`, sorted.
fn xml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            xml_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("xml") {
            out.push(path);
        }
    }
    out.sort();
}

/// The path with `/` separators on every platform (Windows `read_dir` yields `\\`).
fn slashed(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Index of the draft stage a website path belongs to.
fn draft_stage(path: &Path) -> Option<usize> {
    let shown = slashed(path);
    DRAFT_STAGES.iter().position(|s| shown.contains(s))
}

/// How every `kmip/website` XML file is used: run (the cn01 Test Cases notes, and each draft
/// test case that has no run counterpart, once), or accounted for as a duplicate (mirror of a
/// `v*/XML` vector, same stem and same content outside comments and whitespace), a draft of a
/// test case that is run from `v*/XML` or cn01, an older stage or duplicate of a run draft, a
/// KMIP 3.0 draft, or not a KMIP vector (no `<RequestMessage>`).
fn website_classification() -> Vec<(PathBuf, &'static str)> {
    let mut versioned: HashMap<String, Vec<String>> = HashMap::new();
    let mut run_stems: HashSet<String> = HashSet::new();
    for (dir, served) in VERSIONS
        .iter()
        .flat_map(|v| vector_dirs(v).map(|d| (d, *v != "v3.0")))
        .chain(WEBSITE_TEST_CASES.map(|d| (d.to_owned(), true)))
    {
        for path in vector_paths(&dir) {
            let stem = vector_stem(&path).to_owned();
            versioned
                .entry(stem.clone())
                .or_default()
                .push(vector_content(&path));
            if served {
                run_stems.insert(stem);
            }
        }
    }
    let mut website = Vec::new();
    xml_files(Path::new("../../../kmip/website"), &mut website);
    assert!(!website.is_empty(), "no kmip/website vectors found");

    let mut classified: Vec<(PathBuf, &'static str)> = Vec::new();
    // Draft test cases without a run counterpart: (index in `classified`, stem, stage, content).
    let mut candidates: Vec<(usize, String, usize, String)> = Vec::new();
    for path in website {
        let stem = vector_stem(&path).to_owned();
        let text = vector_content(&path);
        let category = if WEBSITE_TEST_CASES
            .iter()
            .any(|d| path.parent() == Some(Path::new(d)))
        {
            CN01
        } else if versioned.get(&stem).is_some_and(|v| v.contains(&text)) {
            MIRROR
        } else if !text.contains("<RequestMessage>") {
            NOT_A_VECTOR
        } else if let Some(stage) = draft_stage(&path) {
            if slashed(&path).contains("/v3.0/") {
                DRAFT_V3
            } else if run_stems.contains(&stem) {
                DRAFT_RUN_ELSEWHERE
            } else {
                candidates.push((classified.len(), stem, stage, text));
                DRAFT_RUN
            }
        } else {
            UNACCOUNTED
        };
        classified.push((path, category));
    }
    // One draft per test case: the newest stage, the first sorted path at equal stage.
    let mut winners: HashMap<&str, &(usize, String, usize, String)> = HashMap::new();
    for candidate in &candidates {
        let best = winners.entry(candidate.1.as_str()).or_insert(candidate);
        if candidate.2 > best.2 {
            *best = candidate;
        }
    }
    for candidate in &candidates {
        let winner = winners[candidate.1.as_str()];
        if winner.0 != candidate.0 {
            classified[candidate.0].1 = if winner.3 == candidate.3 {
                DRAFT_DUPLICATE
            } else {
                DRAFT_SUPERSEDED
            };
        }
    }
    classified
}

/// Draft test cases spread over several files that share objects: each runs as a scenario
/// of its own test (TC-CREG-2/3 locate and destroy what TC-CREG-1 registered).
const DRAFT_SCENARIOS: [&str; 1] = ["TC-CREG-"];

/// The draft test cases run by [`kmip_xml_draft_vectors`] (one file per test case) and, for
/// those starting with `prefix`, by their scenario test.
fn draft_vectors(prefix: Option<&str>) -> Vec<PathBuf> {
    website_classification()
        .into_iter()
        .filter(|(_, category)| *category == DRAFT_RUN)
        .map(|(path, _)| path)
        .filter(|path| {
            let stem = vector_stem(path);
            prefix.map_or_else(
                || !DRAFT_SCENARIOS.iter().any(|p| stem.starts_with(p)),
                |p| stem.starts_with(p),
            )
        })
        .collect()
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_1_4_xml_test_cases_cn01() {
    run_all_xml_vectors_in_dir(WEBSITE_TEST_CASES[0]).await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_0_xml_test_cases_cn01() {
    run_all_xml_vectors_in_dir(WEBSITE_TEST_CASES[1]).await;
}

#[tokio::test]
#[serial_test::serial]
async fn kmip_2_1_xml_test_cases_cn01() {
    run_all_xml_vectors_in_dir(WEBSITE_TEST_CASES[2]).await;
}

/// Draft-stage test cases that no published vector covers, each run once (newest stage).
///
/// Debugging aid: `KMIP_XML_DRAFT_FILTER=a,b` runs only the drafts whose path contains `a` or
/// `b` (for example `kmip-v1.4/TC-DERIVEKEY`); leave it unset for the regression run.
#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_draft_vectors() {
    use test_kms_server::start_default_test_kms_server;

    cosmian_logger::log_init(None);
    let filter = std::env::var("KMIP_XML_DRAFT_FILTER").unwrap_or_default();
    let paths: Vec<PathBuf> = draft_vectors(None)
        .into_iter()
        .filter(|path| {
            let shown = slashed(path);
            filter.is_empty() || filter.split(',').any(|f| shown.contains(f))
        })
        .collect();
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    run_vectors_checked(None, &client, paths.iter().map(PathBuf::as_path)).await;
}

/// Client registration drafts: per protocol version, TC-CREG-1 registers a key pair and a
/// certificate that TC-CREG-2 then gets and TC-CREG-3 destroys, sharing UID placeholders.
#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_creg() {
    use test_kms_server::start_default_test_kms_server;

    cosmian_logger::log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let paths = draft_vectors(Some("TC-CREG-"));
    for version in paths.chunk_by(|a, b| a.parent() == b.parent()) {
        run_vectors_checked(
            Some("kmip_xml_creg"),
            &client,
            version.iter().map(PathBuf::as_path),
        )
        .await;
    }
}

/// Every `.xml` file under `kmip/website` is accounted for exactly once (see
/// [`website_classification`]).
#[test]
fn kmip_xml_website_vectors_accounted() {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut unaccounted = Vec::new();
    let classified = website_classification();
    for (path, category) in &classified {
        if *category == UNACCOUNTED {
            unaccounted.push(path.to_string_lossy().into_owned());
        } else {
            *counts.entry(category).or_default() += 1;
        }
    }
    cosmian_logger::log_init(None);
    cosmian_logger::info!("kmip/website: {} files: {counts:?}", classified.len());
    assert!(
        unaccounted.is_empty(),
        "unaccounted kmip/website vectors: {unaccounted:#?}"
    );
    let stems: Vec<&str> = classified
        .iter()
        .filter(|(_, category)| *category == DRAFT_RUN)
        .map(|(path, _)| vector_stem(path))
        .collect();
    let unique: HashSet<&str> = stems.iter().copied().collect();
    assert_eq!(stems.len(), unique.len(), "a draft test case is run twice");
}

// ─── KMIP 3.0: rejected by the server ──────────────────────────────────────────

/// The 3.0 vectors carry protocol major 3, which the server rejects; several also use
/// 3.0-only operations (Login, Ping, ...) the typed messages cannot hold. Each file is
/// checked to be a 3.0 vector, then a 3.0 request is shown to be refused.
#[tokio::test]
#[serial_test::serial]
async fn kmip_3_0_xml_vectors_rejected() {
    use cosmian_kms_client::cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            },
            kmip_types::ProtocolVersion,
        },
        kmip_2_1::{
            kmip_messages::RequestMessageBatchItem,
            kmip_operations::{Operation, Query},
            kmip_types::{OperationEnumeration, QueryFunction},
        },
        ttlv::{KmipFlavor, TTLV, to_ttlv},
    };
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server;

    let paths: Vec<_> = vector_dirs("v3.0")
        .iter()
        .flat_map(|dir| vector_paths(dir))
        .collect();
    assert!(!paths.is_empty(), "no KMIP 3.0 vectors found");
    for path in &paths {
        let xml = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            xml.contains(r#"ProtocolVersionMajor type="Integer" value="3""#),
            "{}: not a KMIP 3.0 vector",
            path.display()
        );
    }

    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 3,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(256),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: Some(vec![QueryFunction::QueryOperations]),
                    ..Default::default()
                }),
                message_extension: None,
            },
        )],
    };
    let bytes = to_ttlv(&request)
        .and_then(|t| t.to_bytes(KmipFlavor::Kmip2))
        .expect("encode KMIP 3.0 request");
    let url = format!("{}/kmip", client.client.server_url);
    let response = client
        .client
        .post_bytes(&url, bytes, "application/octet-stream")
        .await
        .expect("post KMIP 3.0 request");
    let ttlv = TTLV::from_bytes(response.bytes(), KmipFlavor::Kmip2).expect("decode response");
    let json = serde_json::to_string(&ttlv).expect("serialize response");
    // Binary TTLV carries enumeration values: Operation Failed = 0x01, Unsupported Protocol
    // Version = 0x3F.
    assert!(
        json.contains(r#""tag":"ResultStatus","type":"Enumeration","value":"0x00000001""#)
            && json.contains(r#""tag":"ResultReason","type":"Enumeration","value":"0x0000003F""#),
        "KMIP 3.0 request must be rejected with Unsupported Protocol Version, got: {json}"
    );
}

// ─── Message encodings ─────────────────────────────────────────────────────────

/// The server has no KMIP XML message encoding: the `MSGENC-XML-M-1-*` vectors still run
/// over binary TTLV for their operation semantics, and this test pins the missing encoding.
#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_msgenc_xml_encoding_unsupported() {
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server;

    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let url = format!("{}/kmip", client.client.server_url);
    let response = client
        .client
        .post_bytes(&url, "<RequestMessage/>", "application/xml")
        .await
        .expect("post XML request");
    assert!(
        !response.status.is_success(),
        "XML message encoding unexpectedly accepted: HTTP {}",
        response.status
    );
}

// ─── Table integrity ───────────────────────────────────────────────────────────

/// Every `KNOWN_FAILING`, `DEVIATIONS` and `REASON_DEVIATIONS` entry must name an existing
/// vector file.
#[test]
fn kmip_xml_vector_known_failing_entries_exist() {
    let stems: HashSet<String> = VERSIONS
        .iter()
        .flat_map(|v| vector_dirs(v))
        .chain(WEBSITE_TEST_CASES.map(str::to_owned))
        .flat_map(|dir| vector_paths(&dir))
        .chain(draft_vectors(None))
        .chain(DRAFT_SCENARIOS.iter().flat_map(|p| draft_vectors(Some(p))))
        .map(|path| vector_stem(&path).to_owned())
        .collect();
    for stem in KNOWN_FAILING
        .iter()
        .map(|(s, ..)| *s)
        .chain(DEVIATIONS.iter().map(|d| d.vector))
        .chain(
            REASON_DEVIATIONS
                .iter()
                .flat_map(|d| d.positions.iter().map(|(stem, ..)| *stem)),
        )
    {
        assert!(
            stems.contains(stem),
            "unknown vector stem in deviations.rs: {stem}"
        );
    }
}

// ─── Special: Template Locate (TL) tests ────────────────────────────────────────
//
// TL-M-2 creates a key in the LIBRARY-LTO namespace and TL-M-3 expects Locate to find exactly
// that key. Since all tests share a singleton KMS server, the namespace is emptied before
// the TL vectors of each protocol version.

#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_tl() {
    use cosmian_kms_client::cosmian_kmip::{
        kmip_0::kmip_types::ApplicationSpecificInformation,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::{Destroy, Locate},
        },
    };
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server;

    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let paths = delegated_vector_paths("TL-");
    for version in paths.chunk_by(|a, b| a.parent() == b.parent()) {
        let locate_req = Locate {
            attributes: Attributes {
                application_specific_information: Some(ApplicationSpecificInformation {
                    application_namespace: "LIBRARY-LTO".to_owned(),
                    application_data: Some(
                        "123456789ABCDEF123456789123456789ABCDEF123456789ABCDEF1234000000"
                            .to_owned(),
                    ),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let leftovers = client
            .locate(locate_req.clone())
            .await
            .expect("TL cleanup: locate")
            .unique_identifier
            .unwrap_or_default();
        for uid in leftovers {
            client
                .destroy(Destroy {
                    unique_identifier: Some(uid.clone()),
                    cascade: false,
                    remove: true,
                    expected_object_type: None,
                })
                .await
                .unwrap_or_else(|e| panic!("TL cleanup: destroy {uid}: {e}"));
        }
        let remaining = client
            .locate(locate_req)
            .await
            .expect("TL cleanup: locate")
            .unique_identifier
            .unwrap_or_default();
        assert!(
            remaining.is_empty(),
            "TL cleanup left objects: {remaining:?}"
        );
        run_vectors_checked(
            Some("kmip_xml_tl"),
            &client,
            version.iter().map(PathBuf::as_path),
        )
        .await;
    }
}

// ─── Special: Storage Array with Self-Encrypting Drives (SASED) tests ──────────
//
// SASED-M-2 registers objects in a group that SASED-M-3 then locates: the vectors of each
// protocol version form one scenario sharing UID placeholders.

#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_sased() {
    use cosmian_logger::log_init;
    use test_kms_server::start_default_test_kms_server;

    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let paths = delegated_vector_paths("SASED-");
    for version in paths.chunk_by(|a, b| a.parent() == b.parent()) {
        run_vectors_checked(
            Some("kmip_xml_sased"),
            &client,
            version.iter().map(PathBuf::as_path),
        )
        .await;
    }
}

// ─── Special: PKCS11 tests (SoftHSM2) ──────────────────────────────────────────
//
// The PKCS#11 operation needs an HSM and a configured Crypto Officer. Run with a SoftHSM2
// token (`HSM_SLOT_ID`, `HSM_USER_PASSWORD`, `SOFTHSM2_CONF`), as set up by
// `mise run test:hsm:softhsm2`.

#[ignore = "Requires a SoftHSM2 token: HSM_SLOT_ID, HSM_USER_PASSWORD and SOFTHSM2_CONF"]
#[tokio::test]
#[serial_test::serial]
async fn kmip_xml_pkcs11() {
    use cosmian_logger::log_init;
    use test_kms_server::{TestClientOptions, hsm_config_path, start_test_server_with_patch};

    log_init(None);
    let slot: usize = std::env::var("HSM_SLOT_ID")
        .expect("HSM_SLOT_ID must name the SoftHSM2 slot")
        .parse()
        .expect("HSM_SLOT_ID must be an integer");
    let password = std::env::var("HSM_USER_PASSWORD").unwrap_or_else(|_| "12345678".to_owned());
    let workspace =
        std::env::temp_dir().join(format!("kms_test_xml_pkcs11_{}", std::process::id()));
    let ctx = start_test_server_with_patch(
        &hsm_config_path("softhsm2.toml"),
        |config| {
            config.hsm.hsm_slot = vec![slot];
            config.hsm.hsm_password = vec![password];
            config.key_encryption_key = None;
            // PKCS11 is refused unless a Crypto Officer is configured; the client is `admin`.
            config.roles.crypto_officer_users = Some(vec!["admin".to_owned()]);
            config.db.sqlite_path = workspace.join("sqlite-data");
            config.db.clear_database = true;
            config.workspace.root_data_path = workspace.join("workspace");
            config.workspace.tmp_path = workspace.join("tmp");
        },
        TestClientOptions::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("start SoftHSM2 test server: {e}"));
    let client = ctx.get_owner_client();

    let paths = delegated_vector_paths("PKCS11-");
    run_vectors_checked(
        Some("kmip_xml_pkcs11"),
        &client,
        paths.iter().map(PathBuf::as_path),
    )
    .await;
    ctx.stop_server()
        .await
        .unwrap_or_else(|e| panic!("stop SoftHSM2 test server: {e}"));
}
