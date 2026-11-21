//! No secret may reach a log line or a `Debug` output: private-key integers, credential
//! passwords, byte strings, PKCS#12 password links.

use std::{
    fmt::{Debug, Write as _},
    sync::{Arc, Mutex},
};

use num_bigint_dig::{BigInt, Sign};
use tracing::{
    Event, Metadata,
    field::{Field, Visit},
    span::{Attributes as SpanAttributes, Id, Record},
};

use crate::{
    SafeBigInt, SensitiveBytes,
    kmip_0::kmip_types::{Authentication, Credential, CredentialType, CredentialValue},
    kmip_1_4::{
        kmip_attributes::Attribute as Attribute14,
        kmip_data_structures::EncryptionKeyInformation as EncryptionKeyInformation14,
        kmip_types::{Link as Link14, LinkType as LinkType14},
    },
    kmip_2_1::{
        extra::BulkData,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, PrivateKey},
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{
            EncryptionKeyInformation, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier,
        },
    },
    ttlv::{KmipBigInt, KmipEnumerationVariant, TTLV, TTLValue, from_ttlv, to_ttlv},
};

const MARKER: &str = "SECRET-MARKER";

/// Collects every event message and span field, formatted as `tracing` would record them.
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a mut String);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &SpanAttributes<'_>) -> Id {
        if let Ok(mut out) = self.0.lock() {
            span.record(&mut Fields(&mut out));
        }
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, values: &Record<'_>) {
        if let Ok(mut out) = self.0.lock() {
            values.record(&mut Fields(&mut out));
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if let Ok(mut out) = self.0.lock() {
            event.record(&mut Fields(&mut out));
            out.push('\n');
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Runs `f` with a trace-level capturing subscriber and returns everything it logged.
fn captured_logs(f: impl FnOnce()) -> String {
    let out = Arc::new(Mutex::new(String::new()));
    tracing::subscriber::with_default(Capture(out.clone()), f);
    out.lock().map(|l| l.clone()).unwrap_or_default()
}

/// Fails if `text` contains the marker in any form a derived `Debug`/`Display` or a hex/JSON
/// dump could produce.
fn assert_no_marker(what: &str, text: &str) {
    let bytes = MARKER.as_bytes();
    let byte_list = format!("{bytes:?}");
    let forms = [
        MARKER.to_owned(),
        byte_list[1..byte_list.len() - 1].to_owned(),
        hex::encode(bytes),
        hex::encode_upper(bytes),
        BigInt::from_bytes_be(Sign::Plus, bytes).to_string(),
    ];
    for form in forms {
        assert!(!text.contains(&form), "{what} leaks {form}: {text}");
    }
}

#[test]
fn big_integers_are_redacted_in_debug() {
    // every limb has its high bit set: they take the `LongInteger` path when serialized
    let limbs = [0xF123_4567_u32, 0xE0DE_ADBE, 0xD1BA_DCAF];
    let bytes: Vec<u8> = limbs.iter().flat_map(|l| l.to_be_bytes()).collect();
    let digits: Vec<String> = limbs.iter().map(ToString::to_string).collect();

    let big = KmipBigInt::from(BigInt::from_bytes_be(Sign::Plus, &bytes));
    let outputs = [
        format!("{big:?}"),
        format!("{:?}", SafeBigInt::from_bytes_be(&bytes)),
        format!("{:?}", TTLValue::BigInteger(big)),
    ];
    for out in outputs {
        for digit in &digits {
            assert!(!out.contains(digit.as_str()), "limb {digit} leaked: {out}");
        }
    }
}

#[test]
fn private_key_integers_never_reach_serializer_traces() {
    let limbs = [
        0xF123_4567_u32,
        0xE0DE_ADBE,
        0xD1BA_DCAF,
        0xC001_D00D,
        // below `i32::MAX`: serialized as `Integer` instead of `LongInteger`
        0x1234_5678,
    ];
    let bytes: Vec<u8> = limbs.iter().flat_map(|l| l.to_be_bytes()).collect();
    let private_key = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: Box::new(BigInt::from(65_537)),
                    private_exponent: Some(Box::new(SafeBigInt::from_bytes_be(&bytes))),
                    public_exponent: Some(Box::new(BigInt::from(65_537))),
                    p: None,
                    q: None,
                    prime_exponent_p: None,
                    prime_exponent_q: None,
                    c_r_t_coefficient: None,
                },
                attributes: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let logs = captured_logs(|| {
        drop(to_ttlv(&private_key).unwrap());
    });

    // control: the serializer did log, so the absence below is meaningful
    assert!(
        logs.contains("serializing a struct field"),
        "no trace captured: {logs}"
    );
    for limb in limbs {
        assert!(
            !logs.contains(&limb.to_string()),
            "private exponent limb {limb} reached the trace logs: {logs}"
        );
    }
}

#[test]
fn byte_strings_never_reach_serializer_traces() {
    let encrypt = Encrypt {
        data: Some(SensitiveBytes::from(MARKER.as_bytes().to_vec())),
        i_v_counter_nonce: Some(SensitiveBytes::from(MARKER.as_bytes().to_vec())),
        authenticated_encryption_additional_data: Some(SensitiveBytes::from(
            MARKER.as_bytes().to_vec(),
        )),
        ..Encrypt::default()
    };
    let mut ttlv = None;
    let logs = captured_logs(|| ttlv = Some(to_ttlv(&encrypt).unwrap()));
    assert!(
        logs.contains("Seq Element") || logs.contains("serialize_seq"),
        "{logs}"
    );
    assert_no_marker("serializer traces", &logs);

    let ttlv = ttlv.unwrap();
    assert_no_marker("TTLV Debug", &format!("{ttlv:?} {ttlv:#?}"));
    let logs = captured_logs(|| {
        drop(from_ttlv::<Encrypt>(&ttlv).unwrap());
    });
    assert!(logs.contains("deserialize"), "no trace captured: {logs}");
    assert_no_marker("deserializer traces", &logs);
}

/// Every credential kind that carries a password.
fn credentials() -> Authentication {
    let secret = || Some(MARKER.to_owned());
    Authentication {
        credential: vec![
            Credential {
                credential_type: CredentialType::UsernameAndPassword,
                credential_value: CredentialValue::UsernameAndPassword {
                    username: "alice".to_owned(),
                    password: secret(),
                },
            },
            Credential {
                credential_type: CredentialType::Device,
                credential_value: CredentialValue::Device {
                    device_serial_number: Some("serial".to_owned()),
                    password: secret(),
                    device_identifier: None,
                    network_identifier: None,
                    machine_identifier: None,
                    media_identifier: None,
                },
            },
            Credential {
                credential_type: CredentialType::OneTimePassword,
                credential_value: CredentialValue::OneTimePassword {
                    username: "alice".to_owned(),
                    password: secret(),
                    one_time_password: MARKER.to_owned(),
                },
            },
        ],
    }
}

#[test]
fn credential_passwords_never_reach_logs_or_debug() {
    let authentication = credentials();
    assert_no_marker("Authentication Debug", &format!("{authentication:?}"));

    let mut ttlv = None;
    let logs = captured_logs(|| ttlv = Some(to_ttlv(&authentication).unwrap()));
    assert!(!logs.is_empty(), "no trace captured");
    assert_no_marker("serializer traces", &logs);

    let ttlv = ttlv.unwrap();
    assert_no_marker("TTLV Debug", &format!("{ttlv:?} {ttlv:#?}"));
    let mut parsed = None;
    let logs = captured_logs(|| parsed = Some(from_ttlv::<Authentication>(&ttlv).unwrap()));
    assert!(
        logs.contains("deserialize_str"),
        "no trace captured: {logs}"
    );
    assert_no_marker("deserializer traces", &logs);
    // the secret is still there for the code that needs it
    assert_eq!(parsed.unwrap(), authentication);
}

#[test]
fn pkcs12_password_link_is_redacted() {
    let link = Link {
        link_type: LinkType::PKCS12PasswordLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(MARKER.to_owned()),
    };
    assert_no_marker("Link Debug", &format!("{link:?} {link:#?}"));
    assert_no_marker("Link Display", &link.to_string());

    // other links keep printing their target
    let parent = Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("parent-id".to_owned()),
    };
    assert!(format!("{parent:?}").contains("parent-id"));
    assert!(parent.to_string().contains("parent-id"));

    let mut ttlv = None;
    let logs = captured_logs(|| ttlv = Some(to_ttlv(&link).unwrap()));
    assert!(!logs.is_empty(), "no trace captured");
    assert_no_marker("serializer traces", &logs);
    let ttlv = ttlv.unwrap();
    assert_no_marker("TTLV Debug", &format!("{ttlv:?} {ttlv:#?}"));
    let logs = captured_logs(|| {
        drop(from_ttlv::<Link>(&ttlv).unwrap());
    });
    assert_no_marker("deserializer traces", &logs);
}

#[test]
fn ttlv_debug_keeps_non_secret_values() {
    let ttlv = TTLV {
        tag: "Username".into(),
        value: TTLValue::TextString("alice".to_owned()),
    };
    assert!(format!("{ttlv:?}").contains("alice"));
    let ttlv = TTLV {
        tag: "Password".into(),
        value: TTLValue::TextString(MARKER.to_owned()),
    };
    let out = format!("{ttlv:?}");
    assert!(out.contains("<redacted>") && !out.contains(MARKER), "{out}");
    let ttlv = TTLV {
        tag: "CredentialType".into(),
        value: TTLValue::Enumeration(KmipEnumerationVariant {
            value: 1,
            name: "UsernameAndPassword".into(),
        }),
    };
    assert!(format!("{ttlv:?}").contains("UsernameAndPassword"));
}

#[test]
fn bulk_data_and_requests_print_lengths_only() {
    let bulk = BulkData::new(vec![
        zeroize::Zeroizing::new(MARKER.as_bytes().to_vec()),
        zeroize::Zeroizing::new(MARKER.as_bytes().to_vec()),
    ]);
    let out = format!("{bulk:?}");
    assert_no_marker("BulkData Debug", &out);
    assert!(out.contains('2'), "item count missing: {out}");

    let decrypt = Decrypt {
        data: Some(MARKER.as_bytes().to_vec()),
        ..Decrypt::default()
    };
    assert_no_marker("Decrypt Display", &decrypt.to_string());
}

#[test]
fn kmip_1_4_pkcs12_password_link_is_redacted() {
    let link = Link14 {
        link_type: LinkType14::PKCS12PasswordLink,
        linked_object_identifier: MARKER.to_owned(),
    };
    assert_no_marker("1.4 Link Debug", &format!("{link:?} {link:#?}"));
    // the `{operation:?}` batch item trace reaches links through the attributes
    let attribute = Attribute14::Link(link.clone());
    assert_no_marker(
        "1.4 Attribute Debug",
        &format!("{attribute:?} {attribute:#?}"),
    );

    let parent = Link14 {
        link_type: LinkType14::ParentLink,
        linked_object_identifier: "parent-id".to_owned(),
    };
    assert!(format!("{parent:?}").contains("parent-id"));

    let mut ttlv = None;
    let logs = captured_logs(|| ttlv = Some(to_ttlv(&link).unwrap()));
    assert!(!logs.is_empty(), "no trace captured");
    assert_no_marker("1.4 serializer traces", &logs);
    let ttlv = ttlv.unwrap();
    assert_no_marker("1.4 TTLV Debug", &format!("{ttlv:?} {ttlv:#?}"));
}

/// `ckms certificates export --pkcs12-password` sends the PKCS#12 password as the
/// `UniqueIdentifier` of the `EncryptionKeyInformation`.
#[test]
fn pkcs12_password_in_encryption_key_information_is_redacted() {
    let eki = EncryptionKeyInformation {
        unique_identifier: UniqueIdentifier::TextString(MARKER.to_owned()),
        cryptographic_parameters: None,
    };
    assert_no_marker("EKI Debug", &format!("{eki:?} {eki:#?}"));
    assert_no_marker("EKI Display", &eki.to_string());
    let eki14 = EncryptionKeyInformation14 {
        unique_identifier: MARKER.to_owned(),
        cryptographic_parameters: None,
    };
    assert_no_marker("1.4 EKI Debug", &format!("{eki14:?} {eki14:#?}"));

    let mut ttlv = None;
    let logs = captured_logs(|| ttlv = Some(to_ttlv(&eki).unwrap()));
    assert!(!logs.is_empty(), "no trace captured");
    assert_no_marker("EKI serializer traces", &logs);
    let ttlv = ttlv.unwrap();
    assert_no_marker("EKI TTLV Debug", &format!("{ttlv:?} {ttlv:#?}"));
    let logs = captured_logs(|| {
        drop(from_ttlv::<EncryptionKeyInformation>(&ttlv).unwrap());
    });
    assert_no_marker("EKI deserializer traces", &logs);
}
