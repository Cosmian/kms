use cosmian_kms_client::KmsClient;
use serial_test::serial;

use crate::tests::kms::xml::runner::{
    run_single_xml_vector_on_client as run_single_xml_vector_on_client_generic,
    run_single_xml_vector_with_server as run_single_xml_vector_with_server_generic,
};

// Note: Paths are referenced directly in test macros below; helper resolvers removed to avoid unused warnings.

/// Run a single XML vector using the shared default test server (single sqlite path).
/// test_name is used to namespace UID placeholder keys to avoid cross-test collisions.
pub(crate) async fn run_single_xml_vector(test_name: &str, path: &str) {
    run_single_xml_vector_with_server_generic(test_name, path).await;
}

// Run a single XML vector using an existing client. Useful to chain multiple vectors
// against the same KMS instance (e.g., TL-M-1 -> TL-M-2 -> TL-M-3 sequence).
pub(crate) async fn run_single_xml_vector_on_client(
    test_name: &str,
    client: &KmsClient,
    path: &str,
) {
    run_single_xml_vector_on_client_generic(test_name, client, path).await;
}

// Note: Any pre-seeding helpers were removed; tests do not rely on them currently.

// Hardcoded per-file tests (replacing previous build.rs generation)
macro_rules! xml_test {
    // Pattern: test_name, file
    ($name:ident, $file:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_single_xml_vector(stringify!($name), $file).await;
        }
    };
}

macro_rules! xml_test_group {
    // Pattern: test_name, one or more file paths
    ($name:ident, $($file:expr),+ $(,)?) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            $(
                run_single_xml_vector(stringify!($name), $file).await;
            )+
        }
    };
}

// List derived from files in ../kmip/src/kmip_2_1/specifications/XML/mandatory
// Grouped by prefix - each test runs multiple XML files with the same prefix

// AKLC - Asymmetric Key Lifecycle (3 files)
xml_test_group!(
    kmip_2_1_xml_aklc,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AKLC-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AKLC-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AKLC-M-3-21.xml",
);

// Focused single-file test for AKLC-M-1-21
xml_test!(
    kmip_2_1_xml_aklc_m_1_21_only,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AKLC-M-1-21.xml"
);

// AX - Authentication eXchange (2 files)
xml_test_group!(
    kmip_2_1_xml_ax,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AX-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/AX-M-2-21.xml",
);

// BL - Basic Lifecycle (13 files)
xml_test_group!(
    kmip_2_1_xml_bl,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-4-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-5-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-6-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-7-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-8-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-9-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-10-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-11-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-12-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/BL-M-13-21.xml",
);

// CS-AC - Cryptographic Service - Asymmetric Cryptography (18 files)
xml_test_group!(
    kmip_2_1_xml_cs_ac,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-4-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-5-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-6-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-7-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-8-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-4-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-5-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-6-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-7-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-8-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-9-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-OAEP-10-21.xml",
);

// Focused single-file test for Sign ($SIGNATURE_DATA placeholder substitution)
xml_test!(
    kmip_2_1_xml_cs_ac_m_1_21_only,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-AC-M-1-21.xml"
);

// CS-BC - Cryptographic Service - Block Cryptography (21 files)
xml_test_group!(
    kmip_2_1_xml_cs_bc,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-4-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-5-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-6-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-7-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-8-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-9-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-10-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-11-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-12-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-13-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-14-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-CHACHA20-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-CHACHA20-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-CHACHA20-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-CHACHA20POLY1305-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-GCM-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-GCM-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-BC-M-GCM-3-21.xml",
);

// CS-RNG - Cryptographic Service - Random Number Generation (1 file)
xml_test!(
    kmip_2_1_xml_cs_rng_m_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/CS-RNG-M-1-21.xml"
);

// MSGENC - Message Encoding (3 files)
xml_test_group!(
    kmip_2_1_xml_msgenc,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/MSGENC-HTTPS-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/MSGENC-JSON-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/MSGENC-XML-M-1-21.xml",
);

// OMOS - Object Management and Object State (1 file)
xml_test!(
    kmip_2_1_xml_omos_m_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/OMOS-M-1-21.xml"
);

// PKCS11 - PKCS#11 Interface Compatibility (1 file)
xml_test!(
    kmip_2_1_xml_pkcs11_m_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/PKCS11-M-1-21.xml"
);

// QS - Query Server (2 files)
xml_test_group!(
    kmip_2_1_xml_qs,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/QS-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/QS-M-2-21.xml",
);

// SASED - Secure Authentication Session Establishment and Destruction
xml_test_group!(
    kmip_2_1_xml_sased,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SASED-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SASED-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SASED-M-3-21.xml",
);

// SKFF - Symmetric Key Format and Features (9 files)
xml_test_group!(
    kmip_2_1_xml_skff,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-3-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-4-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-5-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-6-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-7-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-8-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKFF-M-9-21.xml",
);

// SKLC - Symmetric Key Lifecycle (3 files)
xml_test_group!(
    kmip_2_1_xml_sklc,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKLC-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKLC-M-2-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/SKLC-M-3-21.xml",
);

// TL - Template Locate (3 files)
xml_test_group!(
    kmip_2_1_xml_tl_m_3_21,
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/TL-M-1-21.xml",
    "../kmip/src/kmip_2_1/specifications/XML/mandatory/TL-M-2-21.xml",
    // "../kmip/src/kmip_2_1/specifications/XML/mandatory/TL-M-3-21.xml",
);

// Optional vectors (KMIP 2.1 XML optional profile)
// AKLC - Asymmetric Key Lifecycle (optional)
xml_test!(
    kmip_2_1_xml_aklc_o_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/optional/AKLC-O-1-21.xml"
);

// TODO(enable them)
// CS-RNG - Cryptographic Service - Random Number Generation (optional, 4 files)
// xml_test_group!(
//     kmip_2_1_xml_cs_rng_o,
//         "../kmip/src/kmip_2_1/specifications/XML/optional/CS-RNG-O-1-21.xml",
//         "../kmip/src/kmip_2_1/specifications/XML/optional/CS-RNG-O-2-21.xml",
//         "../kmip/src/kmip_2_1/specifications/XML/optional/CS-RNG-O-3-21.xml",
//         "../kmip/src/kmip_2_1/specifications/XML/optional/CS-RNG-O-4-21.xml",
// );

// OMOS - Object Management and Object State (optional)
xml_test!(
    kmip_2_1_xml_omos_o_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/optional/OMOS-O-1-21.xml"
);

// SKLC - Symmetric Key Lifecycle (optional)
xml_test!(
    kmip_2_1_xml_sklc_o_1_21,
    "../kmip/src/kmip_2_1/specifications/XML/optional/SKLC-O-1-21.xml"
);
