use serde::{Deserialize, Serialize};

use crate::{
    KmipError,
    error::result::KmipResult,
    kmip::kmip_types::{Attributes, DerivationMethod, DerivationParameters, UniqueIdentifier},
    ttlv::TTLV,
};

/// KMIP DeriveKey Request
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeriveKeyRequest {
    /// The unique identifier of the object used as the basis for the derivation process
    pub unique_identifier: Option<UniqueIdentifier>,
    /// The method used to derive the new symmetric key value(s) from the existing symmetric key value
    pub derivation_method: Option<DerivationMethod>,
    /// The parameters required for the derivation method
    pub derivation_parameters: Option<DerivationParameters>,
    /// The attributes to be assigned to the derived object
    pub template_attribute: Option<Attributes>,
}

impl DeriveKeyRequest {
    /// Create a new DeriveKey request
    pub fn new(
        unique_identifier: Option<UniqueIdentifier>,
        derivation_method: Option<DerivationMethod>,
        derivation_parameters: Option<DerivationParameters>,
        template_attribute: Option<Attributes>,
    ) -> Self {
        Self {
            unique_identifier,
            derivation_method,
            derivation_parameters,
            template_attribute,
        }
    }
}

impl From<&DeriveKeyRequest> for TTLV {
    fn from(request: &DeriveKeyRequest) -> Self {
        let mut ttlv = TTLV::new_structure("DeriveKeyRequest");

        if let Some(unique_identifier) = &request.unique_identifier {
            ttlv.add_ttlv(unique_identifier.into());
        }

        if let Some(derivation_method) = &request.derivation_method {
            ttlv.add_ttlv(derivation_method.into());
        }

        if let Some(derivation_parameters) = &request.derivation_parameters {
            ttlv.add_ttlv(derivation_parameters.into());
        }

        if let Some(template_attribute) = &request.template_attribute {
            ttlv.add_ttlv(template_attribute.into());
        }

        ttlv
    }
}

impl TryFrom<&TTLV> for DeriveKeyRequest {
    type Error = KmipError;

    fn try_from(ttlv: &TTLV) -> KmipResult<Self> {
        let unique_identifier = ttlv
            .get("UniqueIdentifier")
            .map(UniqueIdentifier::try_from)
            .transpose()?;

        let derivation_method = ttlv
            .get("DerivationMethod")
            .map(DerivationMethod::try_from)
            .transpose()?;

        let derivation_parameters = ttlv
            .get("DerivationParameters")
            .map(DerivationParameters::try_from)
            .transpose()?;

        let template_attribute = ttlv
            .get("TemplateAttribute")
            .map(Attributes::try_from)
            .transpose()?;

        Ok(Self {
            unique_identifier,
            derivation_method,
            derivation_parameters,
            template_attribute,
        })
    }
}

/// KMIP DeriveKey Response
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeriveKeyResponse {
    /// The unique identifier of the newly created derived object
    pub unique_identifier: UniqueIdentifier,
    /// The optional derived object template attribute
    pub template_attribute: Option<Attributes>,
}

impl DeriveKeyResponse {
    /// Create a new DeriveKey response
    pub fn new(
        unique_identifier: UniqueIdentifier,
        template_attribute: Option<Attributes>,
    ) -> Self {
        Self {
            unique_identifier,
            template_attribute,
        }
    }
}

impl From<&DeriveKeyResponse> for TTLV {
    fn from(response: &DeriveKeyResponse) -> Self {
        let mut ttlv = TTLV::new_structure("DeriveKeyResponse");
        ttlv.add_ttlv((&response.unique_identifier).into());

        if let Some(template_attribute) = &response.template_attribute {
            ttlv.add_ttlv(template_attribute.into());
        }

        ttlv
    }
}

impl TryFrom<&TTLV> for DeriveKeyResponse {
    type Error = KmipError;

    fn try_from(ttlv: &TTLV) -> KmipResult<Self> {
        let unique_identifier = ttlv
            .get("UniqueIdentifier")
            .ok_or_else(|| KmipError::InvalidKmipValue("Missing UniqueIdentifier".to_string()))?
            .try_into()?;

        let template_attribute = ttlv
            .get("TemplateAttribute")
            .map(Attributes::try_from)
            .transpose()?;

        Ok(Self {
            unique_identifier,
            template_attribute,
        })
    }
}

/// KMIP DeriveKey Operation
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeriveKey;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kmip::kmip_types::{CryptographicAlgorithm, CryptographicUsageMask};

    #[test]
    fn test_derive_key_request_serialization() {
        let request = DeriveKeyRequest::new(
            Some(UniqueIdentifier::TextString("base-key-id".to_string())),
            Some(DerivationMethod::PBKDF2),
            None,
            Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                ),
                ..Default::default()
            }),
        );

        let ttlv = TTLV::from(&request);
        let deserialized_request = DeriveKeyRequest::try_from(&ttlv).unwrap();
        assert_eq!(request, deserialized_request);
    }

    #[test]
    fn test_derive_key_response_serialization() {
        let response = DeriveKeyResponse::new(
            UniqueIdentifier::TextString("derived-key-id".to_string()),
            None,
        );

        let ttlv = TTLV::from(&response);
        let deserialized_response = DeriveKeyResponse::try_from(&ttlv).unwrap();
        assert_eq!(response, deserialized_response);
    }
}
