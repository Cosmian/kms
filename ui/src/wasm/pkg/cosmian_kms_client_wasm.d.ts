/* tslint:disable */
/* eslint-disable */
export function locate_ttlv_request(tags?: string[] | null, cryptographic_algorithm?: string | null, cryptographic_length?: number | null, key_format_type?: string | null, object_type?: string | null, public_key_id?: string | null, private_key_id?: string | null, certificate_id?: string | null): any;
export function parse_locate_ttlv_response(response: string): any;
export function create_rsa_key_pair_ttlv_request(private_key_id: string | null | undefined, tags: string[], cryptographic_length: number, sensitive: boolean, wrapping_key_id?: string | null): any;
export function create_ec_key_pair_ttlv_request(private_key_id: string | null | undefined, tags: string[], recommended_curve: string, sensitive: boolean, wrapping_key_id?: string | null): any;
export function parse_create_keypair_ttlv_response(response: string): any;
export function create_sym_key_ttlv_request(key_id: string | null | undefined, tags: string[], number_of_bits: number | null | undefined, symmetric_algorithm: string, sensitive: boolean, wrap_key_id?: string | null, wrap_key_b64?: string | null): any;
export function create_secret_data_ttlv_request(secret_type: string, secret_value: string | null | undefined, secret_id: string | null | undefined, tags: string[], sensitive: boolean, wrap_key_id?: string | null): any;
export function parse_create_ttlv_response(response: string): any;
export function decrypt_sym_ttlv_request(key_unique_identifier: string, ciphertext: Uint8Array, authentication_data: Uint8Array | null | undefined, data_encryption_algorithm: any): any;
export function decrypt_rsa_ttlv_request(key_unique_identifier: string, ciphertext: Uint8Array, encryption_algorithm: any, hash_fn: any): any;
export function decrypt_ec_ttlv_request(key_unique_identifier: string, ciphertext: Uint8Array): any;
export function parse_decrypt_ttlv_response(response: string): any;
export function destroy_ttlv_request(unique_identifier: string, remove: boolean): any;
export function parse_destroy_ttlv_response(response: string): any;
export function encrypt_sym_ttlv_request(key_unique_identifier: string, encryption_policy: string | null | undefined, plaintext: Uint8Array, nonce: Uint8Array | null | undefined, authentication_data: Uint8Array | null | undefined, data_encryption_algorithm: any): any;
export function encrypt_rsa_ttlv_request(key_unique_identifier: string, plaintext: Uint8Array, encryption_algorithm: any, hash_fn: any): any;
export function encrypt_ec_ttlv_request(key_unique_identifier: string, plaintext: Uint8Array): any;
export function parse_encrypt_ttlv_response(response: string): any;
export function export_ttlv_request(unique_identifier: string, unwrap: boolean, key_format: string, wrap_key_id?: string | null, wrapping_algorithm?: string | null, authentication_data?: string | null): any;
export function parse_export_ttlv_response(response: string, key_format: string): any;
export function get_rsa_private_key_ttlv_request(key_unique_identifier: string): any;
export function get_rsa_public_key_ttlv_request(key_unique_identifier: string): any;
export function get_ec_private_key_ttlv_request(key_unique_identifier: string): any;
export function get_ec_public_key_ttlv_request(key_unique_identifier: string): any;
export function import_ttlv_request(unique_identifier: string | null | undefined, key_bytes: Uint8Array, key_format: string, public_key_id: string | null | undefined, private_key_id: string | null | undefined, certificate_id: string | null | undefined, unwrap: boolean, replace_existing: boolean, tags: string[], key_usage?: string[] | null, wrapping_key_id?: string | null): any;
export function parse_import_ttlv_response(response: string): any;
export function revoke_ttlv_request(unique_identifier: string, revocation_reason_message: string): any;
export function parse_revoke_ttlv_response(response: string): any;
export function create_cc_master_keypair_ttlv_request(access_structure: string, tags: string[], sensitive: boolean, wrapping_key_id?: string | null): any;
export function create_cc_user_key_ttlv_request(master_secret_key_id: string, access_policy: string, tags: string[], sensitive: boolean, wrapping_key_id?: string | null): any;
export function encrypt_cc_ttlv_request(key_unique_identifier: string, encryption_policy: string, plaintext: Uint8Array, authentication_data?: Uint8Array | null): any;
export function decrypt_cc_ttlv_request(key_unique_identifier: string, ciphertext: Uint8Array, authentication_data?: Uint8Array | null): any;
export function import_certificate_ttlv_request(certificate_id: string | null | undefined, certificate_bytes: Uint8Array, input_format: string, private_key_id: string | null | undefined, public_key_id: string | null | undefined, issuer_certificate_id: string | null | undefined, pkcs12_password: string | null | undefined, replace_existing: boolean, tags: string[], key_usage?: string[] | null): any;
export function export_certificate_ttlv_request(unique_identifier: string, output_format: string, pkcs12_password?: string | null): any;
export function parse_export_certificate_ttlv_response(response: string, output_format: string): any;
export function validate_certificate_ttlv_request(unique_identifier?: string | null, validity_time?: string | null): any;
export function parse_validate_ttlv_response(response: string): any;
export function encrypt_certificate_ttlv_request(unique_identifier: string, plaintext: Uint8Array, authentication_data: Uint8Array | null | undefined, encryption_algorithm: string): any;
export function decrypt_certificate_ttlv_request(unique_identifier: string, ciphertext: Uint8Array, authentication_data: Uint8Array | null | undefined, encryption_algorithm: string): any;
export function certify_ttlv_request(certificate_id: string | null | undefined, certificate_signing_request_format: string | null | undefined, certificate_signing_request: Uint8Array | null | undefined, public_key_id_to_certify: string | null | undefined, certificate_id_to_re_certify: string | null | undefined, generate_key_pair: boolean, subject_name: string | null | undefined, algorithm: string | null | undefined, issuer_private_key_id: string | null | undefined, issuer_certificate_id: string | null | undefined, number_of_days: number, certificate_extensions: Uint8Array | null | undefined, tags: string[]): any;
export function parse_certify_ttlv_response(response: string): any;
export function get_attributes_ttlv_request(unique_identifier: string): any;
export function parse_get_attributes_ttlv_response(response: string, selected_attributes: string[]): any;
export function set_attribute_ttlv_request(unique_identifier: string, attribute_name: string, attribute_value: string): any;
export function parse_set_attribute_ttlv_response(response: string): any;
export function delete_attribute_ttlv_request(unique_identifier: string, attribute_name: string): any;
export function parse_delete_attribute_ttlv_response(response: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly locate_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => void;
  readonly parse_locate_ttlv_response: (a: number, b: number, c: number) => void;
  readonly create_rsa_key_pair_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly create_ec_key_pair_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
  readonly parse_create_keypair_ttlv_response: (a: number, b: number, c: number) => void;
  readonly create_sym_key_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => void;
  readonly create_secret_data_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
  readonly parse_create_ttlv_response: (a: number, b: number, c: number) => void;
  readonly decrypt_sym_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
  readonly decrypt_rsa_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly decrypt_ec_ttlv_request: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly parse_decrypt_ttlv_response: (a: number, b: number, c: number) => void;
  readonly destroy_ttlv_request: (a: number, b: number, c: number, d: number) => void;
  readonly parse_destroy_ttlv_response: (a: number, b: number, c: number) => void;
  readonly encrypt_sym_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
  readonly encrypt_rsa_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly encrypt_ec_ttlv_request: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly parse_encrypt_ttlv_response: (a: number, b: number, c: number) => void;
  readonly export_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
  readonly parse_export_ttlv_response: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly get_rsa_private_key_ttlv_request: (a: number, b: number, c: number) => void;
  readonly get_rsa_public_key_ttlv_request: (a: number, b: number, c: number) => void;
  readonly get_ec_private_key_ttlv_request: (a: number, b: number, c: number) => void;
  readonly get_ec_public_key_ttlv_request: (a: number, b: number, c: number) => void;
  readonly import_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number) => void;
  readonly parse_import_ttlv_response: (a: number, b: number, c: number) => void;
  readonly revoke_ttlv_request: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly parse_revoke_ttlv_response: (a: number, b: number, c: number) => void;
  readonly create_cc_master_keypair_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
  readonly create_cc_user_key_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => void;
  readonly encrypt_cc_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly decrypt_cc_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly import_certificate_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number) => void;
  readonly export_certificate_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly parse_export_certificate_ttlv_response: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly validate_certificate_ttlv_request: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly parse_validate_ttlv_response: (a: number, b: number, c: number) => void;
  readonly encrypt_certificate_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly decrypt_certificate_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => void;
  readonly certify_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number, w: number, x: number, y: number) => void;
  readonly parse_certify_ttlv_response: (a: number, b: number, c: number) => void;
  readonly get_attributes_ttlv_request: (a: number, b: number, c: number) => void;
  readonly parse_get_attributes_ttlv_response: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly set_attribute_ttlv_request: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly parse_set_attribute_ttlv_response: (a: number, b: number, c: number) => void;
  readonly delete_attribute_ttlv_request: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly parse_delete_attribute_ttlv_response: (a: number, b: number, c: number) => void;
  readonly __wbindgen_export_0: (a: number, b: number) => number;
  readonly __wbindgen_export_1: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: (a: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
