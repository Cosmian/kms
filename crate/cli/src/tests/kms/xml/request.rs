use std::collections::HashMap;

use cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;

// Simple aliases to keep field and map types readable
type EncryptArtifacts = (Vec<u8>, Vec<u8>, Vec<u8>);
type AadArtifactsMap = HashMap<Vec<u8>, EncryptArtifacts>;

use cosmian_kmip::{
    kmip_0::{
        self,
        kmip_messages::{
            RequestMessageBatchItemVersioned, ResponseMessage, ResponseMessageBatchItemVersioned,
        },
    },
    kmip_2_1::{self, kmip_operations::Operation, kmip_types::UniqueIdentifier},
};

// Import version-specific artifact updaters
use crate::tests::kms::xml::kmip_1_4::request::update_cached_artifacts_v14;
use crate::tests::kms::xml::kmip_2_1::request::update_cached_artifacts_v21;

/// Contains all the state and artifacts needed for request preparation during KMIP test execution.
/// This struct consolidates the various maps, cached artifacts, and flags that are passed between
/// test iterations to handle placeholder substitution, artifact injection, and state tracking.
pub(crate) struct PrepareRequest {
    /// The current KMIP request message being processed
    pub request: kmip_0::kmip_messages::RequestMessage,
    /// Maps placeholder indices (e.g., from "uid-1") to actual unique identifiers
    pub uid_placeholder_map: HashMap<usize, String>,
    /// Maps AAD bytes to encryption artifacts (ciphertext, IV, tag) for decrypt operations
    pub encrypt_artifacts_by_aad: AadArtifactsMap,
    /// Fallback encryption artifacts from the most recent encrypt operation
    pub last_encrypt_artifacts: Option<EncryptArtifacts>,
    /// Signature data from the most recent sign operation for verification
    pub last_signature_from_sign: Option<Vec<u8>>,
    /// MAC data from the most recent MAC operation for verification
    pub last_mac_from_mac: Option<Vec<u8>>,
    /// Correlation value from the most recent PKCS11 response (for subsequent requests)
    pub last_pkcs11_correlation_value: Option<Vec<u8>>,
    /// Flag indicating if the response should fail with a missing IV error
    pub expected_response_is_missing_iv_error: bool,
    /// Tracks the most recently used unique identifier for implicit injection
    pub last_uid: Option<String>,
    /// Name of the test for namespacing UID placeholders (test-name-uid-N)
    pub test_name: String,
}

impl PrepareRequest {
    /// Creates a new `PrepareRequest` with the given request and empty/default values for other fields
    pub(crate) fn new(request: kmip_0::kmip_messages::RequestMessage, test_name: &str) -> Self {
        Self {
            request,
            uid_placeholder_map: HashMap::new(),
            encrypt_artifacts_by_aad: HashMap::new(),
            last_encrypt_artifacts: None,
            last_signature_from_sign: None,
            last_mac_from_mac: None,
            last_pkcs11_correlation_value: None,
            expected_response_is_missing_iv_error: false,
            last_uid: None,
            test_name: test_name.to_string(),
        }
    }
}

impl PrepareRequest {
    /// Creates a new `PrepareRequest` with an empty request and default values for all fields
    pub(crate) fn with_empty_request(test_name: &str) -> Self {
        use cosmian_kmip::kmip_0::{
            kmip_messages::{RequestMessage, RequestMessageHeader},
            kmip_types::ProtocolVersion,
        };

        let empty_request = RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 1,
                },
                maximum_response_size: None,
                asynchronous_indicator: None,
                authentication: None,
                attestation_capable_indicator: None,
                attestation_type: None,
                batch_error_continuation_option: None,
                batch_order_option: None,
                batch_count: 0,
                client_correlation_value: None,
                server_correlation_value: None,
                time_stamp: None,
            },
            batch_item: Vec::new(),
        };

        Self::new(empty_request, test_name)
    }

    /// Determine if the expected response represents the specific negative test case where a
    /// Decrypt is expected to fail due to a missing IV. We detect this by looking for an
    /// `OperationFailed` + `InvalidMessage` with a `result_message` containing "missing-iv" (case-insensitive).
    pub(crate) fn expected_response_is_missing_iv_error(&mut self, resp: &ResponseMessage) -> bool {
        // Reset flag for this request; only set to true if we positively detect the pattern
        self.expected_response_is_missing_iv_error = false;
        for bi in &resp.batch_item {
            match bi {
                // KMIP 2.1 expected response detection
                ResponseMessageBatchItemVersioned::V21(inner) => {
                    // Fast path: only consider failed operations
                    if format!("{:?}", inner.result_status) != "OperationFailed" {
                        continue;
                    }
                    // Match reason (if present) against Invalid_Message variant name
                    let reason_is_invalid_message = inner
                        .result_reason
                        .map(|r| format!("{r:?}").to_ascii_lowercase())
                        .is_some_and(|s| s.contains("invalid") && s.contains("message"));
                    if !reason_is_invalid_message {
                        continue;
                    }
                    if let Some(msg) = &inner.result_message {
                        if msg.to_ascii_lowercase().contains("missing-iv") {
                            self.expected_response_is_missing_iv_error = true;
                            return true;
                        }
                    }
                }
                // KMIP 1.4 expected response detection
                ResponseMessageBatchItemVersioned::V14(inner) => {
                    // Only consider failed operations
                    if format!("{:?}", inner.result_status) != "OperationFailed" {
                        continue;
                    }
                    // Match reason name in a tolerant, case-insensitive way
                    let reason_is_invalid_message = inner
                        .result_reason
                        .as_ref()
                        .map(|r| format!("{r:?}").to_ascii_lowercase())
                        .is_some_and(|s| s.contains("invalid") && s.contains("message"));
                    if !reason_is_invalid_message {
                        continue;
                    }
                    if let Some(msg) = &inner.result_message {
                        if msg.to_ascii_lowercase().contains("missing-iv") {
                            self.expected_response_is_missing_iv_error = true;
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Consolidated request preparation: applies all placeholder substitutions and injections
    /// needed to make KMIP test vectors work with our KMS implementation.
    pub(crate) fn prepare_request(&mut self) -> (bool, bool) {
        // Apply placeholder substitutions first
        self.substitute_placeholders_in_request();

        // Inject PKCS11 correlation value if needed
        self.inject_pkcs11_correlation_value();

        // Inject implicit UIDs for intra-batch operations that need them
        self.inject_implicit_uids();

        // Inject decrypt artifacts unless we expect a missing IV error
        if !self.expected_response_is_missing_iv_error {
            self.inject_decrypt_artifacts();
        }

        // Inject signature/MAC for verification and track if we did so
        let injected_sig = self.inject_signature_for_verification();
        let injected_mac = self.inject_mac_for_verification();

        (injected_sig, injected_mac)
    }

    /// Update cached artifacts from response for use in subsequent requests
    pub(crate) fn update_cached_artifacts(
        &mut self,
        resp: &ResponseMessage,
        pending_encrypt_aad: &mut Option<Vec<u8>>,
    ) {
        // Delegate to version-specific updaters
        update_cached_artifacts_v21(self, resp, pending_encrypt_aad);
        update_cached_artifacts_v14(self, resp, pending_encrypt_aad);
    }

    /// Capture the AAD bytes of any Encrypt request (if present) before sending so we can
    /// associate it with the subsequent `EncryptResponse` artifacts.
    pub(crate) fn capture_encrypt_request_aad(&self, pending_aad: &mut Option<Vec<u8>>) {
        for bi in &self.request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    if let Operation::Encrypt(enc) = &inner.request_payload {
                        if let Some(aad) = &enc.authenticated_encryption_additional_data {
                            *pending_aad = Some(aad.clone());
                        }
                    }
                }
                RequestMessageBatchItemVersioned::V14(inner) => {
                    if let Op14::Encrypt(enc) = &inner.request_payload {
                        if let Some(aad) = &enc.authenticated_encryption_additional_data {
                            *pending_aad = Some(aad.clone());
                        }
                    }
                }
            }
        }
    }

    fn substitute_placeholders_in_request(&mut self) {
        let request = &mut self.request;
        let uid_map = &self.uid_placeholder_map;
        let test_name = self.test_name.clone();
        for bi in &mut request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    substitute_op_placeholders(&test_name, &mut inner.request_payload, uid_map);
                    // Fallback: if some UID placeholders (e.g., uid-0) remain unresolved
                    // because the map didn't have a value yet, try to replace uid-0 with
                    // the last seen UID captured from prior responses within this vector run.
                    // This mirrors typical KMIP vector semantics where uid-0 refers to the
                    // most recent object when only one is in context.
                    fallback_substitute_with_last_uid(
                        &test_name,
                        &mut inner.request_payload,
                        uid_map,
                        self.last_uid.as_deref(),
                    );
                }
                RequestMessageBatchItemVersioned::V14(inner) => {
                    substitute_op_placeholders_v14(&test_name, &mut inner.request_payload, uid_map);
                    fallback_substitute_with_last_uid_v14(
                        &test_name,
                        &mut inner.request_payload,
                        uid_map,
                        self.last_uid.as_deref(),
                    );
                }
            }
        }
    }

    /// Inject `EncryptResponse` artifacts (ciphertext, IV/nonce, tag) into any Decrypt request
    /// batch items that have missing or empty placeholder fields. Existing non-empty user supplied
    /// fields are preserved.
    fn inject_decrypt_artifacts(&mut self) {
        let request = &mut self.request;
        let artifacts_by_aad: &AadArtifactsMap = &self.encrypt_artifacts_by_aad;
        let fallback_last: Option<&EncryptArtifacts> = self.last_encrypt_artifacts.as_ref();
        // Placeholders recognized in decrypt requests that should be replaced by captured artifacts
        let is_data_placeholder = |v: &Vec<u8>| v.starts_with(b"$DATA"); // e.g., "$DATA_25"
        let is_iv_placeholder = |v: &Vec<u8>| v.as_slice() == b"$IV_COUNTER_NONCE";
        let is_tag_placeholder = |v: &Vec<u8>| v.as_slice() == b"$AUTHENTICATED_ENCRYPTION_TAG";
        for bi in &mut request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    if let Operation::Decrypt(dec) = &mut inner.request_payload {
                        let desired = dec
                            .authenticated_encryption_additional_data
                            .as_ref()
                            .and_then(|aad| artifacts_by_aad.get(aad))
                            .or(fallback_last);
                        if let Some((ciphertext, iv, tag)) = desired {
                            let needs_data = match &dec.data {
                                None => true,
                                Some(d) if d.is_empty() => true,
                                Some(d) if is_data_placeholder(d) => true,
                                _ => false,
                            };
                            if needs_data {
                                dec.data = Some(ciphertext.clone());
                            }
                            let needs_iv = match &dec.i_v_counter_nonce {
                                None => true,
                                Some(v) if v.is_empty() => true,
                                Some(v) if is_iv_placeholder(v) => true,
                                _ => false,
                            };
                            if needs_iv {
                                dec.i_v_counter_nonce = Some(iv.clone());
                            }
                            let needs_tag = match &dec.authenticated_encryption_tag {
                                None => true,
                                Some(v) if v.is_empty() => true,
                                Some(v) if is_tag_placeholder(v) => true,
                                _ => false,
                            };
                            if needs_tag {
                                dec.authenticated_encryption_tag = Some(tag.clone());
                            }
                        }
                    }
                }
                RequestMessageBatchItemVersioned::V14(inner) => {
                    if let Op14::Decrypt(dec) = &mut inner.request_payload {
                        let desired = dec
                            .authenticated_encryption_additional_data
                            .as_ref()
                            .and_then(|aad| artifacts_by_aad.get(aad))
                            .or(fallback_last);
                        if let Some((ciphertext, iv, tag)) = desired {
                            let needs_data = match &dec.data {
                                None => true,
                                Some(d) if d.is_empty() => true,
                                Some(d) if is_data_placeholder(d) => true,
                                _ => false,
                            };
                            if needs_data {
                                dec.data = Some(ciphertext.clone());
                            }
                            let needs_iv = match &dec.i_v_counter_nonce {
                                None => true,
                                Some(v) if v.is_empty() => true,
                                Some(v) if is_iv_placeholder(v) => true,
                                _ => false,
                            };
                            if needs_iv {
                                dec.i_v_counter_nonce = Some(iv.clone());
                            }
                            let needs_tag = match &dec.authenticated_encryption_tag {
                                None => true,
                                Some(v) if v.is_empty() => true,
                                Some(v) if is_tag_placeholder(v) => true,
                                _ => false,
                            };
                            if needs_tag {
                                dec.authenticated_encryption_tag = Some(tag.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Inject the latest captured signature (from a prior `SignResponse`) into any `SignatureVerify`
    /// request payloads that are missing or have empty `signature_data`. Returns true if an
    /// injection occurred (so callers can clear the cached signature).
    fn inject_signature_for_verification(&mut self) -> bool {
        let last_signature = self.last_signature_from_sign.as_ref();
        if last_signature.is_none() {
            return false;
        }
        let mut injected = false;
        // Placeholder markers sometimes used by XML vectors to signal client-side injection
        let sig_placeholder1: &[u8] = b"$SIGNATURE_DATA";
        let sig_placeholder2: &[u8] = b"$SIGNATURE";
        for bi in &mut self.request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    if let Operation::SignatureVerify(v) = &mut inner.request_payload {
                        let needs_sig = match &v.signature_data {
                            None => true,
                            Some(d) if d.is_empty() => true,
                            Some(d) if d.as_slice() == sig_placeholder1 => true,
                            Some(d) if d.as_slice() == sig_placeholder2 => true,
                            _ => false,
                        };
                        if needs_sig {
                            v.signature_data = last_signature.cloned();
                            injected = injected || v.signature_data.is_some();
                        }
                    }
                }
                RequestMessageBatchItemVersioned::V14(inner) => {
                    if let Op14::SignatureVerify(v) = &mut inner.request_payload {
                        let needs_sig = match &v.signature_data {
                            None => true,
                            Some(d) if d.is_empty() => true,
                            Some(d) if d.as_slice() == sig_placeholder1 => true,
                            Some(d) if d.as_slice() == sig_placeholder2 => true,
                            _ => false,
                        };
                        if needs_sig {
                            v.signature_data = last_signature.cloned();
                            injected = injected || v.signature_data.is_some();
                        }
                    }
                }
            }
        }
        injected
    }

    /// Inject the latest captured MAC (from a prior `MACResponse`) into any `MACVerify` request
    /// payloads that are missing or have empty `mac_data`. Returns true if an injection occurred
    /// so caller can clear the cache.
    fn inject_mac_for_verification(&mut self) -> bool {
        let last_mac = self.last_mac_from_mac.as_ref();
        let mut injected = false;
        for bi in &mut self.request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    if let Operation::MACVerify(mv) = &mut inner.request_payload {
                        let needs_mac = mv.mac_data.is_empty();
                        if needs_mac {
                            if let Some(mac) = last_mac {
                                mv.mac_data = mac.clone();
                                injected = true;
                            }
                        }
                    }
                }
                RequestMessageBatchItemVersioned::V14(inner) => {
                    if let Op14::MACVerify(mv) = &mut inner.request_payload {
                        let placeholder = b"$MAC_DATA";
                        let needs_mac =
                            mv.mac_data.is_empty() || mv.mac_data.as_slice() == placeholder;
                        if needs_mac {
                            if let Some(mac) = last_mac {
                                mv.mac_data = mac.clone();
                                injected = true;
                            }
                        }
                    }
                }
            }
        }
        injected
    }

    /// Inject PKCS11 `CorrelationValue` into requests when vectors leave a placeholder or omit it.
    /// Recognizes the literal placeholder "$`CORRELATION_VALUE`" (as bytes) and empty/missing values,
    /// replacing them with the latest correlation captured from a prior `PKCS11Response`.
    fn inject_pkcs11_correlation_value(&mut self) {
        let Some(last_corr) = self.last_pkcs11_correlation_value.as_ref() else {
            return;
        };
        let placeholder = b"$CORRELATION_VALUE";
        for bi in &mut self.request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => {
                    if let Operation::PKCS11(pk) = &mut inner.request_payload {
                        let needs = match &pk.correlation_value {
                            None => true,
                            Some(v) if v.is_empty() => true,
                            Some(v) if v.as_slice() == placeholder => true,
                            _ => false,
                        };
                        if needs {
                            pk.correlation_value = Some(last_corr.clone());
                        }
                    }
                }
                // KMIP 1.4 does not define PKCS11 operations; intentional no-op to mirror V21 structure
                RequestMessageBatchItemVersioned::V14(_) => {
                    // Nothing to inject for 1.4 here
                }
            }
        }
    }

    /// Inject implicit UIDs in the current request based on last seen UID when permitted by
    /// the profile vectors semantics.
    fn inject_implicit_uids(&mut self) {
        let request = &mut self.request;
        let last_uid = &mut self.last_uid;
        for bi in &mut request.batch_item {
            match bi {
                RequestMessageBatchItemVersioned::V21(inner) => match &mut inner.request_payload {
                    Operation::Get(g) => {
                        if g.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                g.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &g.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::GetAttributes(g) => {
                        if g.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                g.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &g.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::GetAttributeList(g) => {
                        if g.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                g.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &g.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::AddAttribute(a) => {
                        if matches!(a.unique_identifier, UniqueIdentifier::TextString(ref s) if s.is_empty())
                        {
                            if let Some(uid) = last_uid.clone() {
                                a.unique_identifier = UniqueIdentifier::TextString(uid);
                            }
                        }
                        if let UniqueIdentifier::TextString(s) = &a.unique_identifier {
                            if !s.is_empty() {
                                *last_uid = Some(s.clone());
                            }
                        }
                    }
                    Operation::ModifyAttribute(m) => {
                        if m.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                m.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &m.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::Export(e) => {
                        if e.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                e.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &e.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::Encrypt(enc) => {
                        if enc.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                enc.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &enc.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::Decrypt(dec) => {
                        if dec.unique_identifier.is_none() {
                            if let Some(uid) = last_uid.clone() {
                                dec.unique_identifier = Some(UniqueIdentifier::TextString(uid));
                            }
                        }
                        if let Some(UniqueIdentifier::TextString(s)) = &dec.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::Destroy(d) => {
                        if let Some(UniqueIdentifier::TextString(s)) = &d.unique_identifier {
                            *last_uid = Some(s.clone());
                        }
                    }
                    Operation::Revoke(r) => {
                        if let Some(UniqueIdentifier::TextString(s)) = &mut r.unique_identifier {
                            // Update last seen
                            *last_uid = Some(s.clone());
                            // Mirror fallback: ensure last_uid points to private key if we accidentally captured a public key variant
                            if let Some(first) = last_uid.clone() {
                                if s == &format!("{first}_pk") {
                                    *s = first;
                                }
                            }
                        }
                    }
                    _ => {}
                },
                RequestMessageBatchItemVersioned::V14(inner) => {
                    use Op14;
                    match &mut inner.request_payload {
                        Op14::Get(g) => {
                            if g.unique_identifier.is_none() {
                                if let Some(uid) = last_uid.clone() {
                                    g.unique_identifier = Some(uid);
                                }
                            }
                            if let Some(s) = &g.unique_identifier {
                                *last_uid = Some(s.clone());
                            }
                        }
                        Op14::GetAttributes(g) => {
                            if g.unique_identifier.is_none() {
                                if let Some(uid) = last_uid.clone() {
                                    g.unique_identifier = Some(uid);
                                }
                            }
                            if let Some(s) = &g.unique_identifier {
                                *last_uid = Some(s.clone());
                            }
                        }
                        Op14::GetAttributeList(g) => {
                            if g.unique_identifier.is_none() {
                                if let Some(uid) = last_uid.clone() {
                                    g.unique_identifier = Some(uid);
                                }
                            }
                            if let Some(s) = &g.unique_identifier {
                                *last_uid = Some(s.clone());
                            }
                        }
                        Op14::AddAttribute(a) => {
                            if a.unique_identifier.is_empty() {
                                if let Some(uid) = last_uid.clone() {
                                    a.unique_identifier = uid;
                                }
                            }
                            if !a.unique_identifier.is_empty() {
                                *last_uid = Some(a.unique_identifier.clone());
                            }
                        }
                        Op14::ModifyAttribute(m) => {
                            if m.unique_identifier.is_none() {
                                if let Some(uid) = last_uid.clone() {
                                    m.unique_identifier = Some(uid);
                                }
                            }
                            if let Some(s) = &m.unique_identifier {
                                *last_uid = Some(s.clone());
                            }
                        }
                        Op14::Export(e) => {
                            if e.unique_identifier.is_empty() {
                                if let Some(uid) = last_uid.clone() {
                                    e.unique_identifier = uid;
                                }
                            }
                            if !e.unique_identifier.is_empty() {
                                *last_uid = Some(e.unique_identifier.clone());
                            }
                        }
                        Op14::Encrypt(enc) => {
                            if enc.unique_identifier.is_empty() {
                                if let Some(uid) = last_uid.clone() {
                                    enc.unique_identifier = uid;
                                }
                            }
                            if !enc.unique_identifier.is_empty() {
                                *last_uid = Some(enc.unique_identifier.clone());
                            }
                        }
                        Op14::Decrypt(dec) => {
                            if dec.unique_identifier.is_empty() {
                                if let Some(uid) = last_uid.clone() {
                                    dec.unique_identifier = uid;
                                }
                            }
                            if !dec.unique_identifier.is_empty() {
                                *last_uid = Some(dec.unique_identifier.clone());
                            }
                        }
                        Op14::Destroy(d) => {
                            if !d.unique_identifier.is_empty() {
                                *last_uid = Some(d.unique_identifier.clone());
                            }
                        }
                        Op14::Revoke(r) => {
                            if let Some(s) = &mut r.unique_identifier {
                                *last_uid = Some(s.clone());
                                if let Some(first) = last_uid.clone() {
                                    if s == &format!("{first}_pk") {
                                        *s = first;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn substitute_op_placeholders(
    test_name: &str,
    op: &mut Operation,
    uid_map: &HashMap<usize, String>,
) {
    match op {
        Operation::Activate(a) => substitute_uid(test_name, &mut a.unique_identifier, uid_map),
        Operation::Get(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
            if let Some(kws) = &mut g.key_wrapping_specification {
                if let Some(eki) = &mut kws.encryption_key_information {
                    substitute_uid(test_name, &mut eki.unique_identifier, uid_map);
                }
                if let Some(mki) = &mut kws.mac_or_signature_key_information {
                    substitute_uid(test_name, &mut mki.unique_identifier, uid_map);
                }
            }
        }
        Operation::GetAttributes(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::GetAttributeList(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::Destroy(d) => {
            if let Some(uid) = &mut d.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::Revoke(r) => {
            if let Some(uid) = &mut r.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::AddAttribute(a) => {
            // Substitute on target UniqueIdentifier
            substitute_uid(test_name, &mut a.unique_identifier, uid_map);
            // Also substitute inside Link attribute payloads (LinkedObjectIdentifier)
            if let cosmian_kmip::kmip_2_1::kmip_attributes::Attribute::Link(link) =
                &mut a.new_attribute
            {
                substitute_linked_uid_in_request(
                    test_name,
                    &mut link.linked_object_identifier,
                    uid_map,
                );
            }
        }
        Operation::DeleteAttribute(d) => {
            if let Some(uid) = &mut d.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::SetAttribute(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
            // Also substitute inside Link attribute payloads (LinkedObjectIdentifier)
            if let cosmian_kmip::kmip_2_1::kmip_attributes::Attribute::Link(link) =
                &mut s.new_attribute
            {
                substitute_linked_uid_in_request(
                    test_name,
                    &mut link.linked_object_identifier,
                    uid_map,
                );
            }
        }
        Operation::Certify(c) => {
            if let Some(uid) = &mut c.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::Export(e) => {
            if let Some(uid) = &mut e.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
            if let Some(kws) = &mut e.key_wrapping_specification {
                if let Some(eki) = &mut kws.encryption_key_information {
                    substitute_uid(test_name, &mut eki.unique_identifier, uid_map);
                }
                if let Some(mki) = &mut kws.mac_or_signature_key_information {
                    substitute_uid(test_name, &mut mki.unique_identifier, uid_map);
                }
            }
        }
        Operation::Encrypt(enc) => {
            if let Some(uid) = &mut enc.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::Decrypt(dec) => {
            if let Some(uid) = &mut dec.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::ModifyAttribute(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
            if let cosmian_kmip::kmip_2_1::kmip_attributes::Attribute::Link(link) =
                &mut m.new_attribute
            {
                substitute_linked_uid_in_request(
                    test_name,
                    &mut link.linked_object_identifier,
                    uid_map,
                );
            }
        }
        Operation::Sign(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::SignatureVerify(v) => {
            if let Some(uid) = &mut v.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::MAC(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        Operation::MACVerify(mv) => {
            substitute_uid(test_name, &mut mv.unique_identifier, uid_map);
        }
        Operation::Check(c) => {
            if let Some(uid) = &mut c.unique_identifier {
                substitute_uid(test_name, uid, uid_map);
            }
        }
        _ => {}
    }
}

// Fallback substitution: if uid-0 (or namespaced/test-name-uid-0, or $UNIQUE_IDENTIFIER_0)
// remains after primary substitution due to missing map entries, and we have a last_uid,
// use it as a pragmatic replacement to keep intra-vector requests working.
fn fallback_substitute_with_last_uid(
    test_name: &str,
    op: &mut Operation,
    uid_map: &HashMap<usize, String>,
    last_uid: Option<&str>,
) {
    let Some(last) = last_uid else {
        return;
    };
    let maybe_fix_uid = |uid: &mut UniqueIdentifier| {
        if let UniqueIdentifier::TextString(s) = uid {
            if let Some(idx) = parse_uid_placeholder_index(test_name, s) {
                if !uid_map.contains_key(&idx) {
                    *s = last.to_string();
                }
            }
        }
    };

    match op {
        Operation::Get(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::GetAttributes(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::GetAttributeList(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Destroy(d) => {
            if let Some(uid) = &mut d.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Revoke(r) => {
            if let Some(uid) = &mut r.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::AddAttribute(a) => {
            maybe_fix_uid(&mut a.unique_identifier);
        }
        Operation::DeleteAttribute(d) => {
            if let Some(uid) = &mut d.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::SetAttribute(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Export(e) => {
            if let Some(uid) = &mut e.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Encrypt(enc) => {
            if let Some(uid) = &mut enc.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Decrypt(dec) => {
            if let Some(uid) = &mut dec.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::ModifyAttribute(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::Sign(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::SignatureVerify(v) => {
            if let Some(uid) = &mut v.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::MAC(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Operation::MACVerify(mv) => {
            maybe_fix_uid(&mut mv.unique_identifier);
        }
        Operation::Check(c) => {
            if let Some(uid) = &mut c.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        _ => {}
    }
}

fn fallback_substitute_with_last_uid_v14(
    test_name: &str,
    op: &mut Op14,
    uid_map: &HashMap<usize, String>,
    last_uid: Option<&str>,
) {
    let Some(last) = last_uid else {
        return;
    };
    let maybe_fix_uid = |uid: &mut String| {
        if let Some(idx) = parse_uid_placeholder_index(test_name, uid) {
            if !uid_map.contains_key(&idx) {
                *uid = last.to_string();
            }
        }
    };

    match op {
        Op14::Get(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::GetAttributes(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::GetAttributeList(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::Destroy(d) => {
            maybe_fix_uid(&mut d.unique_identifier);
        }
        Op14::Revoke(r) => {
            if let Some(uid) = &mut r.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::AddAttribute(a) => {
            maybe_fix_uid(&mut a.unique_identifier);
        }
        Op14::DeleteAttribute(d) => {
            maybe_fix_uid(&mut d.unique_identifier);
        }
        Op14::ModifyAttribute(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::Export(e) => {
            maybe_fix_uid(&mut e.unique_identifier);
        }
        Op14::Encrypt(enc) => {
            maybe_fix_uid(&mut enc.unique_identifier);
        }
        Op14::Decrypt(dec) => {
            maybe_fix_uid(&mut dec.unique_identifier);
        }
        Op14::Sign(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::SignatureVerify(v) => {
            if let Some(uid) = &mut v.unique_identifier {
                maybe_fix_uid(uid);
            }
        }
        Op14::MAC(m) => {
            maybe_fix_uid(&mut m.unique_identifier);
        }
        Op14::MACVerify(mv) => {
            maybe_fix_uid(&mut mv.unique_identifier);
        }
        _ => {}
    }
}

fn substitute_op_placeholders_v14(
    test_name: &str,
    op: &mut Op14,
    uid_map: &HashMap<usize, String>,
) {
    match op {
        Op14::Activate(a) => substitute_uid_text(test_name, &mut a.unique_identifier, uid_map),
        Op14::Get(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
            // Mirror KMIP 2.1: also substitute UIDs inside nested KeyWrappingSpecification
            if let Some(kws) = &mut g.key_wrapping_specification {
                if let Some(eki) = &mut kws.encryption_key_information {
                    substitute_uid_text(test_name, &mut eki.unique_identifier, uid_map);
                }
                if let Some(mki) = &mut kws.mac_signature_key_information {
                    substitute_uid_text(test_name, &mut mki.unique_identifier, uid_map);
                }
            }
        }
        Op14::GetAttributes(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
        }
        Op14::GetAttributeList(g) => {
            if let Some(uid) = &mut g.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
        }
        Op14::Destroy(d) => substitute_uid_text(test_name, &mut d.unique_identifier, uid_map),
        Op14::Revoke(r) => {
            if let Some(uid) = &mut r.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
        }
        Op14::AddAttribute(a) => {
            substitute_uid_text(test_name, &mut a.unique_identifier, uid_map);
            if let cosmian_kmip::kmip_1_4::kmip_attributes::Attribute::Link(link) = &mut a.attribute
            {
                substitute_uid_text(test_name, &mut link.linked_object_identifier, uid_map);
            }
        }
        Op14::DeleteAttribute(d) => {
            substitute_uid_text(test_name, &mut d.unique_identifier, uid_map);
        }
        Op14::ModifyAttribute(m) => {
            if let Some(uid) = &mut m.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
            if let cosmian_kmip::kmip_1_4::kmip_attributes::Attribute::Link(link) = &mut m.attribute
            {
                substitute_uid_text(test_name, &mut link.linked_object_identifier, uid_map);
            }
        }
        Op14::Export(e) => {
            substitute_uid_text(test_name, &mut e.unique_identifier, uid_map);
            // Mirror KMIP 2.1: also substitute UIDs inside nested KeyWrappingSpecification
            if let Some(kws) = &mut e.key_wrapping_specification {
                if let Some(eki) = &mut kws.encryption_key_information {
                    substitute_uid_text(test_name, &mut eki.unique_identifier, uid_map);
                }
                if let Some(mki) = &mut kws.mac_signature_key_information {
                    substitute_uid_text(test_name, &mut mki.unique_identifier, uid_map);
                }
            }
        }
        Op14::Encrypt(enc) => {
            substitute_uid_text(test_name, &mut enc.unique_identifier, uid_map);
        }
        Op14::Decrypt(dec) => {
            substitute_uid_text(test_name, &mut dec.unique_identifier, uid_map);
        }
        Op14::Sign(s) => {
            if let Some(uid) = &mut s.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
        }
        Op14::SignatureVerify(v) => {
            if let Some(uid) = &mut v.unique_identifier {
                substitute_uid_text(test_name, uid, uid_map);
            }
        }
        Op14::MAC(m) => {
            substitute_uid_text(test_name, &mut m.unique_identifier, uid_map);
        }
        Op14::MACVerify(mv) => {
            substitute_uid_text(test_name, &mut mv.unique_identifier, uid_map);
        }
        Op14::Check(c) => {
            substitute_uid_text(test_name, &mut c.unique_identifier, uid_map);
        }
        _ => {}
    }
}

// Substitute a placeholder LinkedObjectIdentifier within KMIP 2.1 request payloads.
// Recognizes raw (uid-N / $UNIQUE_IDENTIFIER_N) and namespaced (test-name-uid-N) placeholders
// and replaces them using the provided uid_map.
fn substitute_linked_uid_in_request(
    test_name: &str,
    uid: &mut cosmian_kmip::kmip_2_1::kmip_types::LinkedObjectIdentifier,
    uid_map: &HashMap<usize, String>,
) {
    use cosmian_kmip::kmip_2_1::kmip_types::LinkedObjectIdentifier as L;
    if let L::TextString(s) = uid {
        if let Some(index) = parse_uid_placeholder_index(test_name, s) {
            if let Some(real) = uid_map.get(&index) {
                *s = real.clone();
            }
        }
    }
}

fn substitute_uid_text(test_name: &str, uid: &mut String, uid_map: &HashMap<usize, String>) {
    // Delegate the placeholder parsing/substitution to substitute_uid by wrapping as UniqueIdentifier::TextString
    let mut ui = UniqueIdentifier::TextString(uid.clone());
    substitute_uid(test_name, &mut ui, uid_map);
    if let UniqueIdentifier::TextString(s) = ui {
        *uid = s;
    }
}

fn substitute_uid(test_name: &str, uid: &mut UniqueIdentifier, uid_map: &HashMap<usize, String>) {
    if let UniqueIdentifier::TextString(s) = uid {
        if let Some(index) = parse_uid_placeholder_index(test_name, s) {
            if let Some(real) = uid_map.get(&index) {
                *s = real.clone();
            }
        }
    }
}

// Single source of truth to parse placeholder index from a UniqueIdentifier text string.
// Supports raw (uid-N / $UNIQUE_IDENTIFIER_N) and namespaced (test-name-uid-N) placeholders.
fn parse_uid_placeholder_index(test_name: &str, s: &str) -> Option<usize> {
    s.strip_prefix(&format!("{test_name}-uid-"))
        .and_then(|n| n.parse::<usize>().ok())
        .map_or_else(
            || {
                s.strip_prefix("uid-")
                    .and_then(|n| n.parse::<usize>().ok())
                    .map_or_else(
                        || {
                            s.strip_prefix("$UNIQUE_IDENTIFIER_")
                                .and_then(|rest| rest.parse::<usize>().ok())
                        },
                        Some,
                    )
            },
            Some,
        )
}

#[cfg(test)]
mod injection_tests {
    use cosmian_kms_client::cosmian_kmip::{
        kmip_0::kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
        },
        kmip_2_1::kmip_operations::{Decrypt, Operation},
    };

    use super::*;

    // Build a minimal RequestMessage containing a single Decrypt operation
    fn build_request(dec: Decrypt) -> RequestMessage {
        RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 1,
                },
                maximum_response_size: None,
                asynchronous_indicator: None,
                authentication: None,
                attestation_capable_indicator: None,
                attestation_type: None,
                batch_error_continuation_option: None,
                batch_order_option: None,
                batch_count: 1,
                client_correlation_value: None,
                server_correlation_value: None,
                time_stamp: None,
            },
            batch_item: vec![RequestMessageBatchItemVersioned::V21(
                kmip_2_1::kmip_messages::RequestMessageBatchItem::new(Operation::Decrypt(
                    Box::new(dec),
                )),
            )],
        }
    }

    #[test]
    fn injects_only_empty_fields() {
        let ciphertext = vec![1, 2, 3];
        let iv = vec![4, 5];
        let tag = vec![6, 7, 8, 9];

        // Pre-populate data (should NOT be overwritten), leave iv & tag empty placeholders
        let dec = Decrypt {
            data: Some(vec![9, 9, 9]),
            i_v_counter_nonce: Some(Vec::new()),
            authenticated_encryption_tag: Some(Vec::new()),
            ..Default::default()
        };
        let mut req = build_request(dec);
        let mut pr = PrepareRequest::new(req.clone(), "injection_tests");
        pr.encrypt_artifacts_by_aad = AadArtifactsMap::default();
        pr.last_encrypt_artifacts = Some((ciphertext, iv.clone(), tag.clone()));
        pr.inject_decrypt_artifacts();
        req = pr.request;

        let RequestMessageBatchItemVersioned::V21(inner) = &req.batch_item[0] else {
            panic!("not v21")
        };
        let Operation::Decrypt(dec) = &inner.request_payload else {
            panic!("not decrypt")
        };
        // Data preserved
        assert_eq!(dec.data.as_ref().unwrap(), &vec![9, 9, 9]);
        // IV and Tag injected
        assert_eq!(dec.i_v_counter_nonce.as_ref().unwrap(), &iv);
        assert_eq!(dec.authenticated_encryption_tag.as_ref().unwrap(), &tag);
    }

    #[test]
    fn injects_all_when_missing() {
        let ciphertext = vec![10];
        let iv = vec![11];
        let tag = vec![12];
        let dec = Decrypt::default(); // all None
        let mut req = build_request(dec);
        let mut pr = PrepareRequest::new(req.clone(), "injection_tests");
        pr.encrypt_artifacts_by_aad = AadArtifactsMap::default();
        pr.last_encrypt_artifacts = Some((ciphertext.clone(), iv.clone(), tag.clone()));
        pr.inject_decrypt_artifacts();
        req = pr.request;
        let RequestMessageBatchItemVersioned::V21(inner) = &req.batch_item[0] else {
            panic!("not v21")
        };
        let Operation::Decrypt(dec) = &inner.request_payload else {
            panic!("not decrypt")
        };
        assert_eq!(dec.data.as_ref().unwrap(), &ciphertext);
        assert_eq!(dec.i_v_counter_nonce.as_ref().unwrap(), &iv);
        assert_eq!(dec.authenticated_encryption_tag.as_ref().unwrap(), &tag);
    }

    #[test]
    fn injects_when_placeholders_present_v21() {
        // Placeholders should be replaced even if the fields are present but contain placeholder markers
        let ciphertext = vec![0xAA, 0xBB];
        let iv = vec![0x01, 0x02, 0x03];
        let tag = vec![0xCC, 0xDD, 0xEE];

        let dec = Decrypt {
            data: Some(b"$DATA_25".to_vec()),
            i_v_counter_nonce: Some(b"$IV_COUNTER_NONCE".to_vec()),
            authenticated_encryption_tag: Some(b"$AUTHENTICATED_ENCRYPTION_TAG".to_vec()),
            ..Default::default()
        };
        let mut req = build_request(dec);
        let mut pr = PrepareRequest::new(req.clone(), "injection_tests");
        pr.encrypt_artifacts_by_aad = AadArtifactsMap::default();
        pr.last_encrypt_artifacts = Some((ciphertext.clone(), iv.clone(), tag.clone()));
        pr.inject_decrypt_artifacts();
        req = pr.request;

        let RequestMessageBatchItemVersioned::V21(inner) = &req.batch_item[0] else {
            panic!("not v21")
        };
        let Operation::Decrypt(dec) = &inner.request_payload else {
            panic!("not decrypt")
        };
        assert_eq!(dec.data.as_ref().unwrap(), &ciphertext);
        assert_eq!(dec.i_v_counter_nonce.as_ref().unwrap(), &iv);
        assert_eq!(dec.authenticated_encryption_tag.as_ref().unwrap(), &tag);
    }
}
