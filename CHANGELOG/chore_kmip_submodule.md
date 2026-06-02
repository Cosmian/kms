## Refactor

- Deduplicate XML test infrastructure in `crate/clients/clap/src/tests/xml/`: extract shared `xml_test!` macro, `compare_common_crypto_responses!` macro, and `update_artifacts_from_payload!` macro to parent modules; KMIP 1.4 and 2.1 test files now reuse shared logic
- Refactor `crate/kmip/src/ttlv/xml/serializer.rs`: introduce `push_typed_value!` macro to eliminate repetitive type-attribute + value push patterns
- Refactor `crate/kmip/src/ttlv/xml/deserializer.rs`: extract `CryptographicUsageMask` token lookup and `AttributeReference` tag lookup into macro-generated top-level functions (`define_usage_mask_lookup!`, `define_attribute_tag_lookup!`)
- Refactor `crate/kmip/src/ttlv/xml/parser.rs`: extract `reconstruct_tag()` helper (was repeated 3×), replace per-call `Regex::new` with `LazyLock<Regex>` statics, pre-compile structural tag regexes via `LazyLock`
- Add `xml_vector_test!` macro in `crate/kmip/src/ttlv/xml/tests/common.rs` to collapse trivial test vector files to single-line macro invocations
- Consolidate `kmip_1_4/kmip.rs` and `kmip_2_1/kmip.rs` into single `xml/kmip.rs` with directory-scanning `run_all_xml_vectors_in_dir` replacing per-file `xml_test!` invocations
- Merge `xml/kmip_1_4/` and `xml/kmip_2_1/` directories into unified `xml/versioned/` module: version-dispatched comparison (`compare_versioned_batch_item`) and artifact extraction (`update_cached_artifacts_versioned`) handle all supported KMIP versions (1.4, 2.1) in a single location, eliminating cross-module macro re-exports

## Bug Fixes

- Fix TTLV XML deserializer: handle explicit `type="Structure"` on self-closing elements (previously caused "unsupported type: Structure" error)
- Fix XML test response comparison: `result_reason` in v1.4 was not being checked (duplicate `result_status` check); now correctly uses lenient comparison for non-success responses
- Fix XML test response comparison: `KeyMaterial::ByteString` and `KeyValue::ByteString` empty match arms no longer silently pass — they now verify length when expected is non-empty
- Fix XML test response comparison: `response_payload` presence mismatch in both v1.4 and v2.1 now correctly returns an error instead of silently passing
