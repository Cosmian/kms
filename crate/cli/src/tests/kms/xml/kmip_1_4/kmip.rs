use cosmian_kms_client::KmsClient;
use serial_test::serial;

use crate::tests::kms::xml::runner::{
    run_single_xml_vector_on_client as run_single_xml_vector_on_client_generic,
    run_single_xml_vector_with_server as run_single_xml_vector_with_server_generic,
};

/// Run a single XML vector using the shared default test server (single sqlite path).
/// `test_name` is used to namespace UID placeholder keys to avoid cross-test collisions.
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

macro_rules! xml_test {
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

// KMIP 1.4 XML mandatory vectors (grouped similarly to kmip_2_1.rs)

// // AKLC - Asymmetric Key Lifecycle (3 files)
xml_test!(
    kmip_1_4_xml_aklc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AKLC-M-3-14.xml",
);

// AX - Authentication eXchange (2 files)
xml_test!(
    kmip_1_4_xml_ax,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AX-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/AX-M-2-14.xml",
);

// CS-AC - Cryptographic Service - Asymmetric Cryptography (Sign/Verify/MAC/OAEP)
xml_test!(
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
xml_test!(
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
xml_test!(
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
xml_test!(
    kmip_1_4_xml_sased,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SASED-M-3-14.xml",
);

// SKFF - Symmetric Key Format and Features (12 files)
xml_test!(
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
xml_test!(
    kmip_1_4_xml_sklc,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-2-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SKLC-M-3-14.xml",
);

// SUITEB (2 files)
xml_test!(
    kmip_1_4_xml_suiteb,
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SUITEB_128-M-1-14.xml",
    "../kmip/src/kmip_1_4/specifications/XML/mandatory/SUITEB_192-M-1-14.xml",
);

// TL - Template Locate (3 files)
// Note: This test suite is sensitive to objects left over from other tests (specifically KMIP 2.1 TL tests)
// because it uses Locate operations that search by ApplicationSpecificInformation.
// We need to ensure a clean state before running these tests.
#[tokio::test]
#[serial]
async fn kmip_1_4_xml_tl() {
    use cosmian_kms_client::cosmian_kmip::{
        kmip_0::kmip_types::ApplicationSpecificInformation,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_operations::{Destroy, Locate},
        },
    };
    use test_kms_server::start_default_test_kms_server;

    // Get the test server
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Clean up any objects with LIBRARY-LTO application specific information
    // that might have been left over from KMIP 2.1 tests
    let locate_req = Locate {
        attributes: Attributes {
            application_specific_information: Some(ApplicationSpecificInformation {
                application_namespace: "LIBRARY-LTO".to_owned(),
                application_data: Some(
                    "123456789ABCDEF123456789123456789ABCDEF123456789ABCDEF1234000000".to_owned(),
                ),
            }),
            ..Default::default()
        },
        ..Default::default()
    };

    if let Ok(locate_resp) = client.locate(locate_req).await {
        for uid in locate_resp.unique_identifier.unwrap_or_default() {
            // Try to destroy each found object - ignore errors as objects might not be destroyable
            drop(
                client
                    .destroy(Destroy {
                        unique_identifier: Some(uid),
                        cascade: false,
                        remove: false,
                    })
                    .await,
            );
        }
    }

    // Now run the actual tests
    run_single_xml_vector(
        "kmip_1_4_xml_tl",
        "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-1-14.xml",
    )
    .await;
    run_single_xml_vector(
        "kmip_1_4_xml_tl",
        "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-2-14.xml",
    )
    .await;
    run_single_xml_vector(
        "kmip_1_4_xml_tl",
        "../kmip/src/kmip_1_4/specifications/XML/mandatory/TL-M-3-14.xml",
    )
    .await;
}

// KMIP 1.4 XML optional vectors

// OMOS - Object Management and Object State (optional)
xml_test!(
    kmip_1_4_xml_omos_o_1_14,
    "../kmip/src/kmip_1_4/specifications/XML/optional/OMOS-O-1-14.xml"
);
