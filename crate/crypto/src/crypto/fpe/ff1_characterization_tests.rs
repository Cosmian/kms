use super::{
    BLOCK_LEN, FF1fr, FF1h, FlexibleNumeralString, KEY_LEN, Prf, aes256_ecb_block, generate_s,
};

fn hex_to_key(hex_str: &str) -> [u8; KEY_LEN] {
    let bytes = hex::decode(hex_str).unwrap();
    let mut key = [0_u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    key
}

fn call_aes256_ecb_block(key: &[u8; KEY_LEN], block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    aes256_ecb_block(key, block).unwrap()
}

fn call_generate_s(key: &[u8; KEY_LEN], r: &[u8; BLOCK_LEN], d: usize) -> Vec<u8> {
    generate_s(key, r, d).unwrap()
}

#[test]
fn characterization_ff1_nist_sample_7() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let ff1 = FF1fr::<10>::new(&key, 10).unwrap();
    let tweak: &[u8] = &[];
    let pt_digits = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let pt = FlexibleNumeralString::from(pt_digits.clone());

    let ct: FlexibleNumeralString = ff1.encrypt(tweak, &pt).unwrap();
    let ct_digits: Vec<u16> = ct.into();
    let expected_ct_digits: Vec<u16> = vec![6, 6, 5, 7, 6, 6, 7, 0, 0, 9];
    assert_eq!(ct_digits, expected_ct_digits);

    let ct_for_dec = FlexibleNumeralString::from(expected_ct_digits);
    let decrypted: FlexibleNumeralString = ff1.decrypt(tweak, &ct_for_dec).unwrap();
    let dec_digits: Vec<u16> = decrypted.into();
    assert_eq!(dec_digits, pt_digits);
}

#[test]
fn characterization_ff1_nist_sample_8() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let ff1 = FF1fr::<10>::new(&key, 10).unwrap();
    let tweak = hex::decode("39383736353433323130").unwrap();
    let pt_digits = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let pt = FlexibleNumeralString::from(pt_digits.clone());

    let ct: FlexibleNumeralString = ff1.encrypt(&tweak, &pt).unwrap();
    let ct_digits: Vec<u16> = ct.into();
    let expected_ct_digits: Vec<u16> = vec![1, 0, 0, 1, 6, 2, 3, 4, 6, 3];
    assert_eq!(ct_digits, expected_ct_digits);

    let ct_for_dec = FlexibleNumeralString::from(expected_ct_digits);
    let decrypted: FlexibleNumeralString = ff1.decrypt(&tweak, &ct_for_dec).unwrap();
    let dec_digits: Vec<u16> = decrypted.into();
    assert_eq!(dec_digits, pt_digits);
}

#[test]
fn characterization_ff1_nist_sample_9() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let ff1 = FF1fr::<10>::new(&key, 36).unwrap();
    let tweak = hex::decode("3737373770717273373737").unwrap();
    // PT: 0123456789abcdefghi (radix 36: 0-9 -> 0-9, a-z -> 10-35)
    let pt_digits: Vec<u16> = vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];
    let pt = FlexibleNumeralString::from(pt_digits.clone());

    let ct: FlexibleNumeralString = ff1.encrypt(&tweak, &pt).unwrap();
    let ct_digits: Vec<u16> = ct.into();
    // xs8a0azh2avyalyzuwd
    let expected_ct_digits: Vec<u16> = vec![
        33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
    ];
    assert_eq!(ct_digits, expected_ct_digits);

    let ct_for_dec = FlexibleNumeralString::from(expected_ct_digits);
    let decrypted: FlexibleNumeralString = ff1.decrypt(&tweak, &ct_for_dec).unwrap();
    let dec_digits: Vec<u16> = decrypted.into();
    assert_eq!(dec_digits, pt_digits);
}

#[test]
fn characterization_ff1h_tweaks_and_decrypt() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let ff1h = FF1h::new(&key, 10).unwrap();
    let pt_digits: Vec<u16> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let pt = FlexibleNumeralString::from(pt_digits.clone());

    let tweak_sizes = [0, 15, 16, 17, 33];
    let expected_goldens: [&[u16]; 5] = [
        &[2, 9, 7, 0, 4, 9, 4, 7, 3, 7],
        &[5, 1, 4, 7, 6, 7, 0, 6, 2, 3],
        &[8, 2, 2, 0, 3, 5, 9, 8, 0, 0],
        &[2, 5, 7, 2, 0, 7, 5, 8, 0, 5],
        &[2, 7, 9, 6, 7, 8, 4, 4, 1, 3],
    ];

    for (tweak_len, expected) in tweak_sizes.iter().zip(expected_goldens.iter()) {
        let tweak = vec![0xA5_u8; *tweak_len];
        let ct: FlexibleNumeralString = ff1h.encrypt(&tweak, &pt).unwrap();
        let ct_digits: Vec<u16> = ct.into();
        assert_eq!(ct_digits, *expected);

        let ct_for_dec = FlexibleNumeralString::from(ct_digits);
        let decrypted: FlexibleNumeralString = ff1h.decrypt(&tweak, &ct_for_dec).unwrap();
        let dec_digits: Vec<u16> = decrypted.into();
        assert_eq!(dec_digits, pt_digits);
    }
}

#[test]
fn characterization_prf_update_chunk_splits() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    // 0 + 1 + 15 + 16 + 17 + 31 = 80 bytes (exactly 5 blocks of 16)
    let full_data = vec![0x42_u8; 80];

    let mut prf_full = Prf::new(&key);
    prf_full.update(&full_data).unwrap();
    let out_full = *prf_full.output();

    let mut prf_chunks = Prf::new(&key);
    let chunk_sizes = [0, 1, 15, 16, 17, 31];
    let mut offset = 0;
    for &size in &chunk_sizes {
        let chunk = full_data.get(offset..offset + size).unwrap();
        prf_chunks.update(chunk).unwrap();
        offset += size;
    }
    let out_chunks = *prf_chunks.output();

    assert_eq!(out_chunks, out_full);
    let expected_hex = "2843af0e33ae5c7b798dd53ade128656";
    assert_eq!(hex::encode(out_chunks), expected_hex);
}

#[test]
fn characterization_generate_s_direct() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let r = [0x5A_u8; BLOCK_LEN];
    let d = 40;
    let s = call_generate_s(&key, &r, d);
    assert_eq!(s.len(), d);
    let expected_hex =
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5aa5bd3ee26b6fd900170f34420e09906a060de4c57003c1ff";
    assert_eq!(hex::encode(&s), expected_hex);
}

#[test]
fn characterization_aes256_ecb_block_direct() {
    let key = hex_to_key("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
    let block = [0x11_u8; BLOCK_LEN];
    let out = call_aes256_ecb_block(&key, &block);
    let expected_hex = "8c0dc059e5bb21fbc37442f7c0878022";
    assert_eq!(hex::encode(out), expected_hex);
}

#[test]
fn characterization_ff1_internal_error_display_names_the_operation() {
    assert_eq!(
        super::NumeralStringError::Internal("AES-256-ECB block encryption").to_string(),
        "FF1 internal error: AES-256-ECB block encryption failed"
    );
}
