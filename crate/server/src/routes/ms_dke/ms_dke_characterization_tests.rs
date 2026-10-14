//! Characterization of `big_int_to_u32` at BASE.

use num_bigint_dig::BigInt;

use super::big_int_to_u32;

#[test]
fn characterization_big_int_to_u32_table() {
    for (label, bu, expected) in [
        ("zero", BigInt::from(0_u8), 0_u32),
        ("one", BigInt::from(1_u8), 1),
        ("65537", BigInt::from(65_537_u32), 65_537),
        ("0x01020304", BigInt::from(0x0102_0304_u32), 16_909_060),
        ("max_u32", BigInt::from(u32::MAX), 4_294_967_295),
        ("0x1_0000_0001", BigInt::from(0x1_0000_0001_u64), 1),
        ("0x0102030405", BigInt::from(0x01_0203_0405_u64), 33_752_069),
        (
            "0xAABBCCDDEEFF",
            BigInt::from(0xAABB_CCDD_EEFF_u64),
            3_437_096_703,
        ),
        ("neg_12", BigInt::from(-12_i32), 12),
        (
            "neg_0x0102030405",
            BigInt::from(-0x01_0203_0405_i64),
            33_752_069,
        ),
        ("256", BigInt::from(256_u32), 256),
        ("0x010000", BigInt::from(0x01_0000_u32), 65_536),
    ] {
        assert_eq!(big_int_to_u32(&bu), expected, "{label}");
    }
}
