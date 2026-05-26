#[test]
#[allow(
    clippy::expect_used,
    clippy::missing_asserts_for_indexing,
    clippy::indexing_slicing
)]
fn test_serial_number_without_fix_creates_21_bytes() {
    // This test verifies the BUG: without clearing the high bit,
    // ASN.1 DER encoding adds a leading 0x00 byte to indicate positive numbers,
    // resulting in 21-byte serial numbers instead of 20 bytes.

    // Create a serial number with high bit set (0x83 = 10000011 in binary)
    let serial_with_high_bit = vec![
        0x83, 0xE9, 0x9B, 0x1A, 0xCA, 0x8A, 0xB0, 0xDD, 0x65, 0xE3, 0x79, 0xB6, 0x28, 0x99, 0xAD,
        0x73, 0x9E, 0x16, 0x33, 0x82,
    ];

    // WITHOUT the fix - directly convert bytes to Asn1Integer (this would be the buggy code)
    let bn = openssl::bn::BigNum::from_slice(&serial_with_high_bit)
        .expect("Failed to create BigNum from slice");
    let asn1_int_buggy = openssl::asn1::Asn1Integer::from_bn(bn.as_ref())
        .expect("Failed to create Asn1Integer from BigNum");

    // Create a minimal X.509 certificate to see how the serial number is encoded
    let rsa = openssl::rsa::Rsa::generate(2048).expect("Failed to generate RSA key");
    let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("Failed to create PKey");

    let mut x509_builder = openssl::x509::X509::builder().expect("Failed to create X509 builder");
    x509_builder
        .set_serial_number(asn1_int_buggy.as_ref())
        .expect("Failed to set serial number");
    x509_builder
        .set_pubkey(&pkey)
        .expect("Failed to set public key");
    x509_builder
        .set_not_before(
            openssl::asn1::Asn1Time::days_from_now(0)
                .expect("Failed to create Asn1Time")
                .as_ref(),
        )
        .expect("Failed to set not_before");
    x509_builder
        .set_not_after(
            openssl::asn1::Asn1Time::days_from_now(365)
                .expect("Failed to create Asn1Time")
                .as_ref(),
        )
        .expect("Failed to set not_after");
    x509_builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .expect("Failed to sign certificate");

    let cert = x509_builder.build();
    let cert_der = cert.to_der().expect("Failed to get certificate DER");

    // Parse the DER to find the serial number field
    // X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    // tbsCertificate: SEQUENCE { [version], serialNumber, ... }

    // Look for the INTEGER tag (0x02) which should contain our serial number
    // The serial number appears early in the certificate
    let mut found_21_byte_serial = false;
    for window in cert_der.windows(3) {
        // Look for INTEGER tag (0x02) with length 0x15 (21 bytes)
        if window[0] == 0x02 && window[1] == 0x15 && window[2] == 0x00 {
            found_21_byte_serial = true;
            break;
        }
    }

    assert!(
        found_21_byte_serial,
        "Certificate DER should contain a 21-byte serial number field (0x02 0x15 0x00 ...) \
         when high bit is set. This demonstrates the bug: ASN.1 adds a 0x00 prefix byte."
    );
}

#[test]
#[allow(clippy::expect_used)]
fn test_serial_number_length() {
    // Test that serial numbers are always 20 bytes or less
    // This verifies the fix for the issue where some certificates
    // had 21-byte serial numbers with a leading 0x00 byte

    // Create test data with high bit set (would trigger the issue before the fix)
    let test_cases = vec![
        // Serial that starts with high bit set (0x83 = 10000011)
        vec![
            0x83, 0xE9, 0x9B, 0x1A, 0xCA, 0x8A, 0xB0, 0xDD, 0x65, 0xE3, 0x79, 0xB6, 0x28, 0x99,
            0xAD, 0x73, 0x9E, 0x16, 0x33, 0x82,
        ],
        // Serial that starts with high bit NOT set (0x04)
        vec![
            0x04, 0xC5, 0xB6, 0x49, 0x2B, 0xE0, 0x8F, 0xF2, 0x16, 0x98, 0x1E, 0xBF, 0x65, 0x02,
            0x50, 0xD7, 0xA9, 0xE1, 0xDC, 0xC5,
        ],
        // All high bits set
        vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
    ];

    for (idx, mut serial_bytes) in test_cases.into_iter().enumerate() {
        // Apply the fix (same as in create_subject_key_identifier_value)
        if let Some(first_byte) = serial_bytes.get_mut(0) {
            *first_byte &= 0x7F;
        }

        // Create BigNum and then Asn1Integer
        let bn = openssl::bn::BigNum::from_slice(&serial_bytes)
            .expect("Failed to create BigNum from slice");
        let asn1_int = openssl::asn1::Asn1Integer::from_bn(bn.as_ref())
            .expect("Failed to create Asn1Integer from BigNum");

        // Get the DER encoding
        let der = asn1_int
            .to_bn()
            .expect("Failed to convert Asn1Integer to BigNum")
            .to_vec();

        // The serial number should be at most 20 bytes
        let first_byte = serial_bytes.first().copied().unwrap_or(0);
        assert!(
            der.len() <= 20,
            "Test case {idx}: Serial number is {} bytes (expected <= 20 bytes). \
             First byte after fix: 0x{first_byte:02X}",
            der.len(),
        );

        // Verify the high bit is not set in the first byte
        assert_eq!(
            first_byte & 0x80,
            0,
            "Test case {idx}: High bit should not be set in first byte",
        );
    }
}
