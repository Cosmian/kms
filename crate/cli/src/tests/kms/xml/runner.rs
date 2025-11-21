use std::path::PathBuf;

use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::{
        kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
        ttlv::xml::KmipXmlDoc,
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::tests::kms::xml::{
    compare::compare_response_messages,
    expected_response::{capture_real_uids_from_response, prepare_expected_response},
    request::PrepareRequest,
};

/// Run a single XML vector by starting a shared default test server.
pub(crate) async fn run_single_xml_vector_with_server(test_name: &str, path: &str) {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    run_single_xml_vector_on_client(test_name, &ctx.get_owner_client(), path).await;
}

/// Core runner used by both KMIP 2.1 and 1.4 suites.
pub(crate) async fn run_single_xml_vector_on_client(
    test_name: &str,
    client: &KmsClient,
    path: &str,
) {
    let path = PathBuf::from(path);
    assert!(
        path.is_file(),
        "XML vector file not found: {}",
        path.display()
    );

    let doc = KmipXmlDoc::new_with_file(&path).expect("parse xml vector");
    assert!(
        doc.requests.len() == doc.responses.len(),
        "{}: mismatched request/response count ({} vs {})",
        path.display(),
        doc.requests.len(),
        doc.responses.len()
    );
    let mut prepare_req = PrepareRequest::with_empty_request(test_name);
    let mut pending_encrypt_aad: Option<Vec<u8>>;

    let requests: Vec<RequestMessage> = doc.requests;
    let responses: Vec<ResponseMessage> = doc.responses;
    for (idx, (request, mut expected_resp)) in requests.into_iter().zip(responses).enumerate() {
        let bi_len = request.batch_item.len();
        assert!(
            bi_len != 0,
            "{}: request with zero batch items",
            path.display()
        );
        assert!(
            usize::try_from(request.request_header.batch_count).unwrap() == bi_len,
            "{}: request batch_count mismatch (header={} actual={})",
            path.display(),
            request.request_header.batch_count,
            bi_len
        );

        prepare_req.request = request;
        pending_encrypt_aad = None;
        prepare_req.capture_encrypt_request_aad(&mut pending_encrypt_aad);
        prepare_req.expected_response_is_missing_iv_error(&expected_resp);
        let (injected_sig, injected_mac) = prepare_req.prepare_request();

        let resp = match client.message(prepare_req.request.clone()).await {
            Ok(r) => r,
            Err(e) => {
                panic!(
                    "{}: send error: {e}. Request: \n{}",
                    path.display(),
                    prepare_req.request
                );
            }
        };

        capture_real_uids_from_response(test_name, &resp, &mut prepare_req.uid_placeholder_map);
        prepare_req.update_cached_artifacts(&resp, &mut pending_encrypt_aad);
        prepare_expected_response(
            test_name,
            &mut expected_resp,
            &resp,
            &prepare_req.uid_placeholder_map,
        );

        if injected_sig {
            prepare_req.last_signature_from_sign = None;
        }
        if injected_mac {
            prepare_req.last_mac_from_mac = None;
        }

        match compare_response_messages(&expected_resp, &resp) {
            Ok(()) => {}
            Err(e) => {
                panic!(
                    "{}: response mismatch at request[{idx}]\n\nRequest: {}\n\nExpected: {expected_resp}\n\nActual: {resp}\n\nError: {e}",
                    path.display(),
                    prepare_req.request
                );
            }
        }
    }
}
