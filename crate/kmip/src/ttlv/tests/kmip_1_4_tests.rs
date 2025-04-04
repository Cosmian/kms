use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::TemplateAttribute,
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicUsageMask, Name,
            NameType, RecommendedCurve,
        },
    },
    ttlv::{from_ttlv, to_ttlv},
};

#[allow(clippy::expect_used)]
#[test]
fn test_template_attributes() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("trace"));

    let template_attribute = TemplateAttribute {
        attribute: Some(vec![
            Attribute::Name(vec![
                Name {
                    name_value: "TestName".to_owned(),
                    name_type: NameType::UninterpretedTextString,
                },
                Name {
                    name_value: "http://localhost".to_owned(),
                    name_type: NameType::URI,
                },
            ]),
            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::EC),
            Attribute::CryptographicLength(128),
            Attribute::CryptographicDomainParameters(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
        ]),
    };

    let ttlv = to_ttlv(&template_attribute).expect("Failed to convert TemplateAttribute to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to TemplateAttribute
    let deserialized_template_attribute: TemplateAttribute =
        from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!(
        "Deserialized TemplateAttribute: {:#?}",
        deserialized_template_attribute
    );
    assert_eq!(
        template_attribute, deserialized_template_attribute,
        "Deserialized TemplateAttribute does not match the original"
    );
}
