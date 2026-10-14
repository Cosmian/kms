//! Characterization tests pinning the BASE behavior of `blob.rs`.

use super::*;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn head_hex(bytes: &[u8], n: usize) -> String {
    to_hex(bytes.get(..n).unwrap())
}

fn tail_hex(bytes: &[u8], n: usize) -> String {
    to_hex(bytes.get(bytes.len() - n..).unwrap())
}

/// DER TLV with short or long-form length.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x02, modulus);
    body.extend_from_slice(&tlv(0x02, exponent));
    tlv(0x30, &body)
}

const RSA_OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

fn rsa_spki(pkcs1: &[u8]) -> Vec<u8> {
    let mut algo_body = tlv(0x06, &RSA_OID);
    algo_body.extend_from_slice(&[0x05, 0x00]);
    let mut bit = vec![0x00];
    bit.extend_from_slice(pkcs1);
    let mut body = tlv(0x30, &algo_body);
    body.extend_from_slice(&tlv(0x03, &bit));
    tlv(0x30, &body)
}

const EC_PUB_OID: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const P256_OID: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const P384_OID: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
const P521_OID: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x23];

fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
    let mut algo_body = tlv(0x06, &EC_PUB_OID);
    algo_body.extend_from_slice(&tlv(0x06, curve_oid));
    let mut bit = vec![0x00];
    bit.extend_from_slice(point);
    let mut body = tlv(0x30, &algo_body);
    body.extend_from_slice(&tlv(0x03, &bit));
    tlv(0x30, &body)
}

fn point(coord: usize) -> Vec<u8> {
    let mut p = vec![0x04];
    p.extend((0..coord).map(|i| u8::try_from(i + 1).unwrap()));
    p.extend((0..coord).map(|i| u8::try_from(0xF0 - i).unwrap()));
    p
}

const RSA_PUB_PKCS1_BLOB: &str = "525341312000000003000000040000000000000000000000010001c0010203";

#[test]
fn characterization_rsa_public_blob_small() {
    let blob = rsa_public_blob(&[0x01, 0x00, 0x01], &[0xC0, 0x01, 0x02, 0x03]);
    assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
}

#[test]
fn characterization_rsa_public_blob_empty() {
    assert_eq!(
        to_hex(&rsa_public_blob(&[], &[])),
        "525341310000000000000000000000000000000000000000"
    );
}

#[test]
fn characterization_rsa_public_blob_2048() {
    let modulus: Vec<u8> = (0..256_u16).map(|i| u8::try_from(i).unwrap()).collect();
    let blob = rsa_public_blob(&[0x01, 0x00, 0x01], &modulus);
    assert_eq!(blob.len(), 24 + 3 + 256);
    assert_eq!(
        head_hex(&blob, 24),
        "525341310008000003000000000100000000000000000000"
    );
    assert_eq!(tail_hex(&blob, 4), "fcfdfeff");
}

#[test]
fn characterization_rsa_public_blob_from_pkcs1_der_strips_sign_byte() {
    let der = pkcs1_der(&[0x00, 0xC0, 0x01, 0x02, 0x03], &[0x01, 0x00, 0x01]);
    assert_eq!(to_hex(&der), "300c020500c00102030203010001");
    let blob = rsa_public_blob_from_pkcs1_der(&der).unwrap();
    assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
}

#[test]
fn characterization_rsa_public_blob_from_pkcs1_der_keeps_non_sign_zero_free() {
    let der = pkcs1_der(&[0x7F, 0x01], &[0x03]);
    let blob = rsa_public_blob_from_pkcs1_der(&der).unwrap();
    assert_eq!(
        to_hex(&blob),
        "525341311000000001000000020000000000000000000000037f01"
    );
}

#[test]
fn characterization_rsa_public_blob_from_pkcs1_der_errors() {
    let err = |d: &[u8]| rsa_public_blob_from_pkcs1_der(d).unwrap_err().to_string();
    assert_eq!(err(&[]), "invalid parameter: DER too short");
    assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
    assert_eq!(
        err(&[0x31, 0x00]),
        "invalid parameter: Expected SEQUENCE in RSA public key"
    );
    assert_eq!(
        err(&[0x30, 0x05, 0x01]),
        "invalid parameter: DER value truncated"
    );
    assert_eq!(
        err(&[0x30, 0x81]),
        "invalid parameter: DER length truncated"
    );
    assert_eq!(
        err(&tlv(0x30, &[0x03, 0x01, 0x05, 0x02, 0x01, 0x03])),
        "invalid parameter: Expected INTEGER (modulus)"
    );
    assert_eq!(
        err(&tlv(0x30, &[0x02, 0x01, 0x05, 0x03, 0x01, 0x03])),
        "invalid parameter: Expected INTEGER (exponent)"
    );
    assert_eq!(
        err(&tlv(0x30, &[0x02, 0x01, 0x05])),
        "invalid parameter: DER too short"
    );
}

#[test]
fn characterization_der_read_tlv_long_forms() {
    // 0x81 form, 0x84 form with leading zero length bytes, and trailing data returned.
    let (val, rest) = der_read_tlv(&[0x04, 0x81, 0x02, 0xAA, 0xBB, 0xCC]).unwrap();
    assert_eq!((val, rest), (&[0xAA, 0xBB][..], &[0xCC][..]));
    let (val, rest) = der_read_tlv(&[0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0xAA]).unwrap();
    assert_eq!((val, rest), (&[0xAA][..], &[][..]));
    let (val, rest) = der_read_tlv(&[0x04, 0x00]).unwrap();
    assert_eq!((val, rest), (&[][..], &[][..]));
    // The tag byte is not checked.
    let (val, _) = der_read_tlv(&[0xFF, 0x01, 0x09]).unwrap();
    assert_eq!(val, &[0x09][..]);
}

#[test]
fn characterization_strip_leading_zero() {
    assert_eq!(strip_leading_zero(&[0, 1, 2]), &[1, 2][..]);
    assert_eq!(strip_leading_zero(&[0, 0, 2]), &[0, 2][..]);
    let empty: &[u8] = &[];
    assert_eq!(strip_leading_zero(&[0]), empty);
    assert_eq!(strip_leading_zero(&[]), empty);
    assert_eq!(strip_leading_zero(&[5, 0]), &[5, 0][..]);
}

#[test]
fn characterization_rsa_public_blob_from_spki_der() {
    let der = pkcs1_der(&[0x00, 0xC0, 0x01, 0x02, 0x03], &[0x01, 0x00, 0x01]);
    let spki = rsa_spki(&der);
    assert_eq!(
        to_hex(&spki),
        "3020300d06092a864886f70d0101010500030f00300c020500c00102030203010001"
    );
    let blob = rsa_public_blob_from_spki_der(&spki).unwrap();
    assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
}

#[test]
fn characterization_rsa_public_blob_from_spki_der_errors() {
    let err = |d: &[u8]| rsa_public_blob_from_spki_der(d).unwrap_err().to_string();
    assert_eq!(err(&[]), "invalid parameter: Expected SPKI SEQUENCE");
    assert_eq!(
        err(&[0x31, 0x00]),
        "invalid parameter: Expected SPKI SEQUENCE"
    );
    assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
    // algorithm sequence only, no BIT STRING (rest is empty)
    assert_eq!(
        err(&tlv(0x30, &tlv(0x30, &[0x05, 0x00]))),
        "invalid parameter: Expected BIT STRING in SPKI"
    );
    // second element is not a BIT STRING
    let mut body = tlv(0x30, &[0x05, 0x00]);
    body.extend_from_slice(&tlv(0x04, &[0x00, 0x01]));
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: Expected BIT STRING in SPKI"
    );
    // empty BIT STRING
    let mut body = tlv(0x30, &[0x05, 0x00]);
    body.extend_from_slice(&[0x03, 0x00]);
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: BIT STRING too short"
    );
    // inner PKCS#1 not a sequence
    let mut body = tlv(0x30, &[0x05, 0x00]);
    body.extend_from_slice(&tlv(0x03, &[0x00, 0x31, 0x00]));
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: Expected SEQUENCE in RSA public key"
    );
}

#[test]
fn characterization_ec_curve_tables() {
    assert_eq!(EcCurve::P256.coord_size(), 32);
    assert_eq!(EcCurve::P384.coord_size(), 48);
    assert_eq!(EcCurve::P521.coord_size(), 66);
    assert_eq!(EcCurve::P256.ecdsa_public_magic(), 0x3153_4345);
    assert_eq!(EcCurve::P384.ecdsa_public_magic(), 0x3353_4345);
    assert_eq!(EcCurve::P521.ecdsa_public_magic(), 0x3553_4345);
    assert_eq!(EcCurve::P256.ecdh_public_magic(), 0x314B_4345);
    assert_eq!(EcCurve::P384.ecdh_public_magic(), 0x334B_4345);
    assert_eq!(EcCurve::P521.ecdh_public_magic(), 0x354B_4345);
}

#[test]
fn characterization_ec_public_blob_all_curves() {
    for (curve, coord, ecdsa, head, tail) in [
        (EcCurve::P256, 32, true, "4543533120000000", "d4d3d2d1"),
        (EcCurve::P256, 32, false, "45434b3120000000", "d4d3d2d1"),
        (EcCurve::P384, 48, true, "4543533330000000", "c4c3c2c1"),
        (EcCurve::P384, 48, false, "45434b3330000000", "c4c3c2c1"),
        (EcCurve::P521, 66, true, "4543533542000000", "b2b1b0af"),
        (EcCurve::P521, 66, false, "45434b3542000000", "b2b1b0af"),
    ] {
        let p = point(coord);
        let x = p.get(1..=coord).unwrap();
        let y = p.get(1 + coord..).unwrap();
        {
            let blob = ec_public_blob(curve, x, y, ecdsa);
            assert_eq!(blob.len(), 8 + 2 * coord);
            assert_eq!(head_hex(&blob, 8), head);
            assert_eq!(tail_hex(&blob, 4), tail);
        }
    }
}

#[test]
fn characterization_ec_public_blob_from_uncompressed_ok_and_errors() {
    let p = point(32);
    let blob = ec_public_blob_from_uncompressed(EcCurve::P256, &p, true).unwrap();
    assert_eq!(
        blob,
        ec_public_blob(
            EcCurve::P256,
            p.get(1..33).unwrap(),
            p.get(33..).unwrap(),
            true
        )
    );
    let blob = ec_public_blob_from_uncompressed(EcCurve::P256, &p, false).unwrap();
    assert_eq!(head_hex(&blob, 8), "45434b3120000000");

    let msg = "invalid parameter: EC point must be uncompressed (0x04 prefix)";
    let mut bad = p.clone();
    *bad.first_mut().unwrap() = 0x02;
    assert_eq!(
        ec_public_blob_from_uncompressed(EcCurve::P256, &bad, true)
            .unwrap_err()
            .to_string(),
        msg
    );
    assert_eq!(
        ec_public_blob_from_uncompressed(EcCurve::P256, p.get(..64).unwrap(), true)
            .unwrap_err()
            .to_string(),
        msg
    );
    assert_eq!(
        ec_public_blob_from_uncompressed(EcCurve::P384, &p, true)
            .unwrap_err()
            .to_string(),
        msg
    );
    assert_eq!(
        ec_public_blob_from_uncompressed(EcCurve::P256, &[], true)
            .unwrap_err()
            .to_string(),
        msg
    );
}

#[test]
fn characterization_ec_public_blob_from_spki_der_curves() {
    for (oid, curve, coord) in [
        (&P256_OID[..], EcCurve::P256, 32),
        (&P384_OID[..], EcCurve::P384, 48),
        (&P521_OID[..], EcCurve::P521, 66),
    ] {
        let p = point(coord);
        let spki = ec_spki(oid, &p);
        for ecdsa in [true, false] {
            assert_eq!(
                ec_public_blob_from_spki_der(&spki, ecdsa).unwrap(),
                ec_public_blob_from_uncompressed(curve, &p, ecdsa).unwrap()
            );
        }
    }
    let spki = ec_spki(&P256_OID, &point(32));
    assert_eq!(
        to_hex(&spki),
        "3059301306072a8648ce3d020106082a8648ce3d030107034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
    );
}

#[test]
fn characterization_ec_public_blob_from_spki_der_errors() {
    let err = |d: &[u8]| {
        ec_public_blob_from_spki_der(d, true)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(err(&[]), "invalid parameter: Expected SPKI SEQUENCE");
    assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
    assert_eq!(
        err(&tlv(0x30, &tlv(0x31, &[]))),
        "invalid parameter: Expected AlgorithmIdentifier SEQUENCE"
    );
    assert_eq!(
        err(&tlv(0x30, &tlv(0x30, &tlv(0x04, &[1])))),
        "invalid parameter: Expected OID in AlgorithmIdentifier"
    );
    assert_eq!(
        err(&tlv(0x30, &tlv(0x30, &tlv(0x06, &EC_PUB_OID)))),
        "invalid parameter: Expected curve OID in AlgorithmIdentifier"
    );
    let mut algo = tlv(0x06, &EC_PUB_OID);
    algo.extend_from_slice(&tlv(0x06, &[0x2A, 0x86]));
    assert_eq!(
        err(&tlv(0x30, &tlv(0x30, &algo))),
        "algorithm not supported: Unsupported EC curve OID: [2a, 86]"
    );
    let mut algo = tlv(0x06, &EC_PUB_OID);
    algo.extend_from_slice(&tlv(0x06, &P256_OID));
    let mut body = tlv(0x30, &algo);
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: Expected BIT STRING in EC SPKI"
    );
    body.extend_from_slice(&tlv(0x04, &[0, 1]));
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: Expected BIT STRING in EC SPKI"
    );
    let mut body = tlv(0x30, &algo);
    body.extend_from_slice(&[0x03, 0x00]);
    assert_eq!(
        err(&tlv(0x30, &body)),
        "invalid parameter: BIT STRING too short"
    );
}

/// Build a `BCRYPT_RSAFULLPRIVATE_BLOB` with the given field lengths; each
/// field is filled with a distinct byte pattern.
fn full_private_blob(cb_e: usize, cb_n: usize, cb_p: usize, cb_q: usize) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&BCRYPT_RSAFULLPRIVATE_MAGIC.to_le_bytes());
    blob.extend_from_slice(&u32::try_from(cb_n * 8).unwrap().to_le_bytes());
    for cb in [cb_e, cb_n, cb_p, cb_q] {
        blob.extend_from_slice(&u32::try_from(cb).unwrap().to_le_bytes());
    }
    for (fill, len) in [
        (0x01_u8, cb_e),
        (0x11, cb_n),
        (0x21, cb_p),
        (0x31, cb_q),
        (0x41, cb_p),
        (0x51, cb_q),
        (0x61, cb_p),
        (0x71, cb_n),
    ] {
        blob.extend((0..len).map(|i| fill.wrapping_add(u8::try_from(i % 7).unwrap())));
    }
    blob
}

#[test]
fn characterization_pkcs8_from_rsa_full_private_blob_small() {
    let blob = full_private_blob(3, 8, 2, 3);
    assert_eq!(
        to_hex(&blob),
        "52534133400000000300000008000000020000000300000001020311121314151617112122313233414251525361627172737475767771"
    );
    let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
    assert_eq!(
        to_hex(&der),
        "3048020100300d06092a864886f70d0101010500043430320201000208111213141516171102030102030208717273747576777102022122020331323302024142020351525302026162"
    );
}

#[test]
fn characterization_pkcs8_from_rsa_full_private_blob_sign_and_zero_padding() {
    // e = 00 00 03 (leading zeros stripped), n starts with 0x80 (sign pad),
    // p = 00 00 (all zeros -> single zero), q = 0x7f.. no pad.
    let mut blob = Vec::new();
    blob.extend_from_slice(&BCRYPT_RSAFULLPRIVATE_MAGIC.to_le_bytes());
    for v in [32_u32, 3, 4, 2, 1] {
        blob.extend_from_slice(&v.to_le_bytes());
    }
    blob.extend_from_slice(&[0, 0, 3]); // e
    blob.extend_from_slice(&[0x80, 0, 0, 1]); // n
    blob.extend_from_slice(&[0, 0]); // p
    blob.extend_from_slice(&[0x7F]); // q
    blob.extend_from_slice(&[0, 0]); // dp
    blob.extend_from_slice(&[0xFF]); // dq
    blob.extend_from_slice(&[0, 0]); // qinv
    blob.extend_from_slice(&[0x80, 0, 0, 2]); // d
    // NB: the blob parser uses cb_prime1 = 2 and cb_prime2 = 1 here via header [.., 2, 1].
    let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
    assert_eq!(
        to_hex(&der),
        "303a020100300d06092a864886f70d010101050004263024020100020500800000010201030205008000000202010002017f020100020200ff020100"
    );
}

#[test]
fn characterization_pkcs8_from_rsa_full_private_blob_trailing_bytes_ignored() {
    let mut blob = full_private_blob(3, 8, 2, 3);
    let plain = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
    blob.extend_from_slice(&[0xEE; 5]);
    assert_eq!(pkcs8_from_rsa_full_private_blob(&blob).unwrap(), plain);
}

#[test]
fn characterization_pkcs8_from_rsa_full_private_blob_der_length_forms() {
    // 0x81 (modulus 200), 0x82 (modulus 300), 0x83 (modulus 70000) encodings.
    for (cb_n, len, head) in [
        (200, 474, "308201d6020100300d06092a864886f70d01010105000482"),
        (300, 676, "308202a0020100300d06092a864886f70d01010105000482"),
        (
            70_000,
            140_081,
            "308302232c020100300d06092a864886f70d010101050004",
        ),
    ] {
        let blob = full_private_blob(3, cb_n, 4, 4);
        let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
        assert_eq!(der.len(), len);
        assert_eq!(head_hex(&der, 24), head);
        assert_eq!(tail_hex(&der, 8), "5354020461626364");
    }
}

#[test]
fn characterization_pkcs8_from_rsa_full_private_blob_errors() {
    let err = |d: &[u8]| pkcs8_from_rsa_full_private_blob(d).unwrap_err().to_string();
    assert_eq!(
        err(&[]),
        "invalid parameter: RSA full private blob too short for header"
    );
    assert_eq!(
        err(&[0; 23]),
        "invalid parameter: RSA full private blob too short for header"
    );
    assert_eq!(
        err(&[0; 24]),
        "invalid parameter: Expected RSA3 magic (0x33415352), got 0x00000000"
    );
    let mut blob = rsa_public_blob(&[1], &[2]);
    assert_eq!(
        err(&blob),
        "invalid parameter: Expected RSA3 magic (0x33415352), got 0x31415352"
    );
    blob = full_private_blob(3, 8, 2, 3);
    blob.pop();
    assert_eq!(
        err(&blob),
        "invalid parameter: RSA full private blob too short: need 55, got 54"
    );
}

#[test]
fn characterization_der_encode_helpers() {
    assert_eq!(der_encode_uint(&[0]), vec![0x02, 0x01, 0x00]);
    assert_eq!(der_encode_uint(&[]), vec![0x02, 0x00]);
    assert_eq!(der_encode_uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    assert_eq!(der_encode_uint(&[0, 0, 0x7F]), vec![0x02, 0x01, 0x7F]);
    for (len, expected) in [
        (0_usize, vec![0x00]),
        (0x7F, vec![0x7F]),
        (0x80, vec![0x81, 0x80]),
        (0xFF, vec![0x81, 0xFF]),
        (0x100, vec![0x82, 0x01, 0x00]),
        (0xFFFF, vec![0x82, 0xFF, 0xFF]),
        (0x1_0000, vec![0x83, 0x01, 0x00, 0x00]),
        (0x12_3456, vec![0x83, 0x12, 0x34, 0x56]),
    ] {
        let mut out = Vec::new();
        der_encode_length(&mut out, len);
        assert_eq!(out, expected, "len {len}");
    }
}
