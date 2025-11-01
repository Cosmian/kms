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

pub(crate) async fn run_single_xml_vector_on_client(
    test_name: &str,
    client: &KmsClient,
    path: &str,
) {
    run_single_xml_vector_on_client_generic(test_name, client, path).await;
}

macro_rules! xml_test_group {
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

macro_rules! xml_test {
    ($name:ident, $file:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_single_xml_vector(stringify!($name), $file).await;
        }
    };
}

// KMIP 1.4 XML mandatory vectors (grouped similarly to kmip_2_1.rs)

// // AKLC - Asymmetric Key Lifecycle (3 files)
xml_test_group!(
    kmip_1_4_xml_aklc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-3-14.xml",
);

// AX - Authentication eXchange (2 files)
xml_test_group!(
    kmip_1_4_xml_ax,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AX-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AX-M-2-14.xml",
);

// CS-AC - Cryptographic Service - Asymmetric Cryptography (Sign/Verify/MAC/OAEP)
xml_test_group!(
    kmip_1_4_xml_cs_ac,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-3-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-4-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-5-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-6-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-7-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-8-14.xml",
    // OAEP variants
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-3-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-4-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-5-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-6-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-7-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-8-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-9-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-AC-M-OAEP-10-14.xml",
);

// CS-BC - Cryptographic Service - Block Cryptography
xml_test_group!(
    kmip_1_4_xml_cs_bc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-3-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-4-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-5-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-6-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-7-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-8-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-9-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-10-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-11-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-12-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-13-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-14-14.xml",
    // GCM modes
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-GCM-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-GCM-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-BC-M-GCM-3-14.xml",
);

// CS-RNG - Cryptographic Service - Random Number Generation (1 file)
xml_test!(
    kmip_1_4_xml_cs_rng_m_1_14,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/CS-RNG-M-1-14.xml"
);

// MSGENC - Message Encoding (3 files)
xml_test_group!(
    kmip_1_4_xml_msgenc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/MSGENC-HTTPS-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/MSGENC-JSON-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/MSGENC-XML-M-1-14.xml",
);

// OMOS - Object Management and Object State (1 file)
xml_test!(
    kmip_1_4_xml_omos_m_1_14,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/OMOS-M-1-14.xml"
);

// SASED - Secure Authentication Session Establishment and Destruction (3 files)
xml_test_group!(
    kmip_1_4_xml_sased,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-3-14.xml",
);

// SKFF - Symmetric Key Format and Features (12 files)
xml_test_group!(
    kmip_1_4_xml_skff,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-3-14.xml",
    // Skipped: SKFF-M-4-14 (3DES key creation) is not supported by the server policy
    // "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-4-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-5-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-6-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-7-14.xml",
    // Skipped: SKFF-M-8-14 uses 3DES which is not supported
    // "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-8-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-9-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-10-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-11-14.xml",
    // Skipped: SKFF-M-12-14 uses 3DES which is not supported
    // "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKFF-M-12-14.xml",
);

// SKLC - Symmetric Key Lifecycle (3 files)
xml_test_group!(
    kmip_1_4_xml_sklc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-3-14.xml",
);

// SUITEB (2 files)
xml_test_group!(
    kmip_1_4_xml_suiteb,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SUITEB_128-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SUITEB_192-M-1-14.xml",
);

// TL - Template Locate (3 files)
xml_test_group!(
    kmip_1_4_xml_tl,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-3-14.xml",
);

// KMIP 1.4 XML optional vectors

// AKLC - Asymmetric Key Lifecycle (optional)
// xml_test!(
//     kmip_1_4_xml_aklc_o_1_14,
//     "../kmip/src/kmip_1_4/specifications/XML/optional/AKLC-O-1-14.xml"
// );

// CS-RNG - Random Number Generation (optional, 4 files)
// xml_test_group!(
//     kmip_1_4_xml_cs_rng_o,
//     "../kmip/src/kmip_1_4/specifications/XML/optional/CS-RNG-O-1-14.xml",
//     "../kmip/src/kmip_1_4/specifications/XML/optional/CS-RNG-O-2-14.xml",
//     "../kmip/src/kmip_1_4/specifications/XML/optional/CS-RNG-O-3-14.xml",
//     "../kmip/src/kmip_1_4/specifications/XML/optional/CS-RNG-O-4-14.xml",
// );

// OMOS - Object Management and Object State (optional)
xml_test!(
    kmip_1_4_xml_omos_o_1_14,
    "../kmip/src/kmip_1_4/specifications/XML/optional/OMOS-O-1-14.xml"
);

// SKLC - Symmetric Key Lifecycle (optional)
// xml_test!(
//     kmip_1_4_xml_sklc_o_1_14,
//     "../kmip/src/kmip_1_4/specifications/XML/optional/SKLC-O-1-14.xml"
// );
