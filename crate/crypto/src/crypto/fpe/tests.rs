#![allow(
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::float_cmp,
    clippy::needless_for_each
)]
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use rand::{Rng, RngCore, SeedableRng, thread_rng};
use rand_chacha::ChaCha20Rng;
use rand_distr::Alphanumeric;

use super::{Alphabet, FPEError, Float, Integer, KEY_LENGTH, decrypt_fpe, encrypt_fpe};

/// Generate a random key using a cryptographically
/// secure random number generator that is suitable for use with FPE
fn random_key() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut key = [0_u8; KEY_LENGTH];
    rng.fill_bytes(&mut key);
    key
}

fn alphabet_check(plaintext: &str, alphabet: &Alphabet, non_alphabet_chars: &str) {
    let key = random_key();
    let ciphertext = alphabet.encrypt(&key, &[], plaintext).unwrap();
    eprintln!("  {:?} -> {:?} ", &plaintext, &ciphertext);
    assert_eq!(plaintext.chars().count(), ciphertext.chars().count());
    // every character of the generated string should be part of the alphabet or a -
    // or a ' '
    let non_alphabet_u16 = non_alphabet_chars.chars().collect::<Vec<char>>();
    for c in ciphertext.chars() {
        assert!(non_alphabet_u16.contains(&c) || alphabet.char_to_position(c).is_some());
    }
    let cleartext = alphabet.decrypt(&key, &[], ciphertext.as_str()).unwrap();
    assert_eq!(cleartext, plaintext);
}

#[test]
fn test_doc_example() -> Result<(), FPEError> {
    let alphabet = Alphabet::alpha_lower(); //same as above
    let key = [0_u8; 32];
    let tweak = b"unique tweak";
    let plaintext = "plaintext";
    let ciphertext = alphabet.encrypt(&key, tweak, plaintext)?;
    assert_eq!(ciphertext, "phqivnqmo");
    let cleartext = alphabet.decrypt(&key, tweak, &ciphertext)?;
    assert_eq!(cleartext, plaintext);
    Ok(())
}

#[test]
fn test_readme_examples() -> Result<(), FPEError> {
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let alphabet = Alphabet::alpha_numeric(); //0-9a-zA-Z
        let ciphertext = alphabet.encrypt(&key, tweak, "alphanumeric").unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("jraqSuFWZmdH", ciphertext);
        assert_eq!("alphanumeric", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let alphabet = Alphabet::numeric(); //0-9
        let ciphertext = alphabet
            .encrypt(&key, tweak, "1234-1234-1234-1234")
            .unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("1415-4650-5562-7272", ciphertext);
        assert_eq!("1234-1234-1234-1234", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let mut alphabet = Alphabet::chinese();
        // add the space character to the alphabet
        alphabet.extend_with(" ");
        let ciphertext = alphabet.encrypt(&key, tweak, "天地玄黄 宇宙洪荒").unwrap();
        let plaintext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
        assert_eq!("儖濣鈍媺惐墷礿截媃", ciphertext);
        assert_eq!("天地玄黄 宇宙洪荒", plaintext);
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // decimal number with digits 0-9
        let radix = 10_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 999_999
        let digits = 6;

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt(&key, tweak, 123_456_u64).unwrap();
        let plaintext = itg.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(110_655_u64, ciphertext);
        assert_eq!(123_456_u64, plaintext);
    }

    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // hexadecimal number with digits 0-9
        let radix = 16_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 16_777_215
        let digits = 6;

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt(&key, tweak, 123_456_u64).unwrap();
        let plaintext = itg.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(1_687_131_u64, ciphertext);
        assert_eq!(123_456_u64, plaintext);
    }

    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        // decimal number with digits 0-9
        let radix = 10_u32;
        // the number of digits of the greatest number = radix^digits -1
        // In this case 6 decimal digits -> 999_999
        let digits = 20;

        // the value to encrypt: 10^17
        let value = BigUint::from_str_radix("100000000000000000", radix).unwrap();

        let itg = Integer::instantiate(radix, digits).unwrap();
        let ciphertext = itg.encrypt_big(&key, tweak, &value).unwrap();
        let plaintext = itg.decrypt_big(&key, tweak, &ciphertext).unwrap();

        assert_eq!(
            BigUint::from_str_radix("65348521845006160218", radix).unwrap(),
            ciphertext
        );
        assert_eq!(
            BigUint::from_str_radix("100000000000000000", radix).unwrap(),
            plaintext
        );
    }
    {
        let key = [0_u8; 32];
        let tweak = b"unique tweak";

        let flt = Float::instantiate().unwrap();
        let ciphertext = flt.encrypt(&key, tweak, 123_456.789_f64).unwrap();
        let plaintext = flt.decrypt(&key, tweak, ciphertext).unwrap();

        assert_eq!(1.170_438_892_319_619e91_f64, ciphertext);
        assert_eq!(123_456.789_f64, plaintext);
    }

    Ok(())
}

#[test]
fn test_kmip_fpe_text_roundtrip() -> Result<(), FPEError> {
    let key = [0_u8; 32];
    let tweak = b"unique tweak";
    let plaintext = b"1234-5678-9012-3456";

    let ciphertext = encrypt_fpe(&key, plaintext, Some(b"numeric"), Some(tweak))?;
    assert_eq!(plaintext.len(), ciphertext.len());
    assert_ne!(ciphertext, plaintext);

    let decrypted = decrypt_fpe(&key, &ciphertext, Some(b"numeric"), Some(tweak))?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_kmip_fpe_integer_roundtrip() -> Result<(), FPEError> {
    let key = [0_u8; 32];
    let tweak = b"integer tweak";
    let plaintext = b"123456";
    let metadata = br#"{"type":"integer","alphabet":"numeric"}"#;

    let ciphertext = encrypt_fpe(&key, plaintext, Some(metadata), Some(tweak))?;
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_ne!(ciphertext, plaintext);

    let decrypted = decrypt_fpe(&key, &ciphertext, Some(metadata), Some(tweak))?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_kmip_fpe_float_roundtrip() -> Result<(), FPEError> {
    let key = [0_u8; 32];
    let tweak = b"float tweak";
    let plaintext = b"123456.789";
    let metadata = br#"{"type":"float"}"#;

    let ciphertext = encrypt_fpe(&key, plaintext, Some(metadata), Some(tweak))?;
    assert_ne!(ciphertext, plaintext);

    let decrypted = decrypt_fpe(&key, &ciphertext, Some(metadata), Some(tweak))?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn fpe_ff1_credit_card_number() -> Result<(), FPEError> {
    let alphabet = Alphabet::numeric();
    [
        "1234-1234-1234-1234",
        "0000-0000-0000-0000",
        "1234-5678-9012-3456",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, "-"));
    Ok(())
}

#[test]
fn fpe_ff1_names() -> Result<(), FPEError> {
    // alphanumeric test
    let mut alphabet = Alphabet::alpha();

    ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    // extended with space and dash
    alphabet.extend_with(" -");
    ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcd"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, ""));

    // lower case
    let alphabet = Alphabet::alpha_lower();
    ["John Doe", "Alba Martinez-Gonzalez", "MalcolmX", "abcde"]
        .iter()
        .for_each(|n| alphabet_check(&n.to_lowercase(), &alphabet, " -"));

    // extended with French characters
    let alphabet = Alphabet::latin1sup();
    ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    // extended with French characters
    let alphabet = Alphabet::latin1sup_alphanum();
    ["Goûter", "René La Taupe", "Bérangère Aigüe", "Ça va bien"]
        .iter()
        .for_each(|n| alphabet_check(n, &alphabet, " -"));

    let alphabet = Alphabet::utf();
    [
        "Bérangère Aigüe",
        "ПРС-ТУФХЦЧШЩЪЫЬ ЭЮЯаб-вгдежз ийклмнопрст уфхцчш",
        "吢櫬䀾羑襃￥",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, " -"));

    let alphabet = Alphabet::chinese();
    [
        "天地玄黄 宇宙洪荒",
        "日月盈昃 辰宿列张",
        "寒来暑往 秋收冬藏",
    ]
    .iter()
    .for_each(|n| alphabet_check(n, &alphabet, " -"));

    Ok(())
}

#[test]
fn fpe_ff1_string_same_alphabet() -> Result<(), FPEError> {
    for _ in 0..100 {
        let plaintext_len = thread_rng().gen_range(8..257);
        let plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_len)
            .map(char::from)
            .collect();
        let alphabet = Alphabet::try_from(&plaintext)?;
        alphabet_check(&plaintext, &alphabet, "");
    }
    Ok(())
}

fn fpe_number_u64_(radix: u32, min_length: usize) -> Result<(), FPEError> {
    let key = random_key();
    let mut rng = thread_rng();
    for _i in 0..20 {
        let digits = rng.gen_range(min_length..min_length + 9);
        let itg = Integer::instantiate(radix, digits)?;
        for _j in 0..10 {
            let value = rng.gen_range(0..itg.max_value.to_u64().unwrap());
            let ciphertext = itg.encrypt(&key, &[], value)?;
            assert!(ciphertext <= itg.max_value().to_u64().unwrap());
            assert_eq!(itg.decrypt(&key, &[], ciphertext)?, value);
        }
    }

    Ok(())
}

#[test]
fn fpe_number_u64() -> Result<(), FPEError> {
    for i in 2..=16 {
        let min_length =
            super::ff1::radix_min_len(i).map_err(|e| FPEError::OutOfBounds(e.to_string()))?;
        fpe_number_u64_(i, min_length)?;
    }
    Ok(())
}

#[test]
fn fpe_number_big_uint() -> Result<(), FPEError> {
    let key = random_key();
    let mut rng = thread_rng();
    for radix in 2..=16 {
        let base = BigUint::from(radix);
        for _i in 0..20 {
            let digits = rng.gen_range(24..32);
            let number = Integer::instantiate(radix, digits)?;
            for _j in 0..10 {
                let exponent = rng.gen_range(0..digits - 1);
                let value = base.pow(exponent.to_u32().unwrap());
                let ciphertext = number.encrypt_big(&key, &[], &value)?;
                assert!(ciphertext <= number.max_value());
                assert_eq!(number.decrypt_big(&key, &[], &ciphertext)?, value);
            }
        }
    }

    Ok(())
}

#[test]
fn fpe_float() -> Result<(), FPEError> {
    let key = random_key();
    let mut rng = thread_rng();
    let float = Float::instantiate()?;
    for _i in 0..1000 {
        let value = rng.gen_range(0.0..f64::MAX);
        let ciphertext = float.encrypt(&key, &[], value)?;
        assert_eq!(float.decrypt(&key, &[], ciphertext)?, value);
    }
    Ok(())
}

#[test]
fn test_negative_cases() -> Result<(), FPEError> {
    // Wrong key size: Alphabet::encrypt and decrypt should reject a 16-byte key
    let alphabet = Alphabet::alpha_lower();
    let bad_key = [0_u8; 16];
    assert!(
        alphabet.encrypt(&bad_key, &[], "abcdefghij").is_err(),
        "encrypt should reject a 16-byte key"
    );
    assert!(
        alphabet.decrypt(&bad_key, &[], "abcdefghij").is_err(),
        "decrypt should reject a 16-byte key"
    );

    // Invalid alphabet: too few characters
    assert!(
        Alphabet::try_from("a").is_err(),
        "single-char alphabet must fail"
    );
    assert!(Alphabet::try_from("").is_err(), "empty alphabet must fail");

    // Plaintext too short: alpha_lower has 26 chars, min_plaintext_length(26) == 5
    let key = random_key();
    assert!(
        alphabet.encrypt(&key, &[], "abcd").is_err(),
        "plaintext shorter than minimum should fail"
    );

    // Radix out of range for Integer
    assert!(Integer::instantiate(0, 6).is_err(), "radix 0 must fail");
    assert!(Integer::instantiate(1, 6).is_err(), "radix 1 must fail");
    assert!(Integer::instantiate(17, 6).is_err(), "radix 17 must fail");

    // Too few digits for the given radix (radix 10 needs at least 6 digits)
    assert!(
        Integer::instantiate(10, 5).is_err(),
        "5 digits for radix-10 should fail"
    );

    Ok(())
}

#[test]
fn fpe_ff1_ascii_printable() -> Result<(), FPEError> {
    let key = random_key();
    let alphabet = Alphabet::ascii_printable();

    // Alphabet covers all 95 printable ASCII characters including space
    assert_eq!(alphabet.alphabet_len(), 95);
    assert!(
        alphabet.char_to_position(' ').is_some(),
        "space must be in the alphabet"
    );
    assert!(
        alphabet.char_to_position('~').is_some(),
        "tilde must be in the alphabet"
    );
    assert!(
        alphabet.char_to_position('\x1F').is_none(),
        "control chars must not be in the alphabet"
    );

    // All characters in the sample are in the alphabet — none are preserved outside FPE
    let samples = [
        "Hello, World!",
        "addr: 42 rue de Rivoli",
        "{'key': 'val', 'n': 123}",
    ];
    for plaintext in samples {
        alphabet_check(plaintext, &alphabet, "");
    }

    // Round-trip with tweak
    let ciphertext = alphabet.encrypt(&key, b"my-tweak", "Free text, with punctuation!")?;
    let decrypted = alphabet.decrypt(&key, b"my-tweak", &ciphertext)?;
    assert_eq!(decrypted, "Free text, with punctuation!");
    assert_eq!(
        ciphertext.chars().count(),
        "Free text, with punctuation!".chars().count()
    );

    Ok(())
}

#[test]
fn fpe_ff1_base64() -> Result<(), FPEError> {
    let key = random_key();
    let alphabet = Alphabet::base64();

    // Alphabet has exactly 64 characters: A-Z a-z 0-9 + /
    assert_eq!(alphabet.alphabet_len(), 64);
    assert!(
        alphabet.char_to_position('+').is_some(),
        "+ must be in the alphabet"
    );
    assert!(
        alphabet.char_to_position('/').is_some(),
        "/ must be in the alphabet"
    );
    // '=' is intentionally excluded
    assert!(
        alphabet.char_to_position('=').is_none(),
        "= must NOT be in the alphabet"
    );

    // Unpadded Base64 — all characters are in the alphabet, none pass-through
    alphabet_check("SGVsbG8gV29ybGQ", &alphabet, "");

    // Padded Base64 — '=' padding is preserved verbatim (non-alphabet pass-through)
    let padded = "SGVsbG8gV29ybGQ=";
    let ciphertext = alphabet.encrypt(&key, b"tweak", padded)?;
    // Ciphertext and plaintext must have the same length
    assert_eq!(ciphertext.chars().count(), padded.chars().count());
    // The trailing '=' must still be '=' in the ciphertext
    assert_eq!(
        ciphertext.chars().last(),
        Some('='),
        "'=' padding must be preserved verbatim"
    );
    let decrypted = alphabet.decrypt(&key, b"tweak", &ciphertext)?;
    assert_eq!(decrypted, padded);

    // Double-padding variant: "test" -> "dGVzdA==" (6 non-padding chars before ==)
    let double_padded = "dGVzdA==";
    let ct2 = alphabet.encrypt(&key, b"tweak", double_padded)?;
    assert_eq!(ct2.chars().count(), double_padded.chars().count());
    assert!(ct2.ends_with("=="), "double '==' padding must be preserved");
    let dec2 = alphabet.decrypt(&key, b"tweak", &ct2)?;
    assert_eq!(dec2, double_padded);

    Ok(())
}
