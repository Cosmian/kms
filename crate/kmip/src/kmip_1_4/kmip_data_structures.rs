use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[allow(clippy::wildcard_imports)]
use super::kmip_types::*;

/// 2.1.1 Attribute Object Structure
/// An Attribute object is a structure used to hold the name, index and value of a
/// managed object (Object, Template-Attribute or Attribute). The Attribute structure
/// consists of an Attribute Name, Index and Value fields.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Attribute {
    pub attribute_name: String,
    pub attribute_index: Option<i32>,
    pub attribute_value: AttributeValue,
}

/// Attribute Value variants
/// The Attribute Value type is a variant used to represent the different possible
/// value types that can be contained within an Attribute structure.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum AttributeValue {
    Integer(i32),
    LongInteger(i64),
    BigInteger(Vec<u8>),
    Enumeration(i32),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(DateTime<Utc>),
    Interval(i32),
    Structure(Vec<Attribute>),
}

/// 2.1.2 Credential Object Structure
/// A Credential is a structure used to convey information used to authenticate a client
/// or server to the other party in a KMIP message. It contains credential type and
/// credential value fields.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub credential_type: CredentialType,
    pub credential_value: CredentialValue,
}

/// Credential Value variants
/// The Credential Value type contains specific authentication credential values based
/// on the credential type.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum CredentialValue {
    UsernameAndPassword {
        username: String,
        password: String,
    },
    Device {
        device_serial_number: Option<String>,
        password: Option<String>,
        device_identifier: Option<String>,
        network_identifier: Option<String>,
        machine_identifier: Option<String>,
        media_identifier: Option<String>,
    },
    Attestation {
        nonce: Vec<u8>,
        attestation_measurement: Option<Vec<u8>>,
        attestation_assertion: Option<Vec<u8>>,
    },
}

/// 2.1.3 Key Block Object Structure
/// A Key Block object is a structure used to encapsulate all of the information that is
/// closely associated with a cryptographic key. It contains information about the format
/// of the key, the algorithm it supports, and its cryptographic length.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_value: KeyValue,
    pub cryptographic_algorithm: CryptographicAlgorithm,
    pub cryptographic_length: i32,
    pub key_wrapping_data: Option<KeyWrappingData>,
}

/// 2.1.4 Key Value Object Structure
/// The Key Value object is a structure used to represent the key material and associated
/// attributes within a Key Block structure.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyValue {
    pub key_material: Vec<u8>,
    pub attributes: Option<Vec<Attribute>>,
}

/// 2.1.5 Key Wrapping Data Object Structure
/// The Key Wrapping Data object is a structure that contains information about the
/// wrapping of a key value. It includes the wrapping method, encryption key information,
/// MAC/signature information, initialization vector/counter/nonce if applicable, and
/// encoding information.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    pub mac_signature: Option<Vec<u8>>,
    pub iv_counter_nonce: Option<Vec<u8>>,
    pub encoding_option: Option<EncodingOption>,
}

/// Encryption Key Information Structure
/// The Encryption Key Information is a structure containing a unique identifier and
/// optional parameters used to encrypt the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionKeyInformation {
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// MAC/Signature Key Information Structure
/// The MAC/Signature Key Information is a structure containing a unique identifier and
/// optional parameters used to generate a MAC or signature over the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct MacSignatureKeyInformation {
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// 2.1.6 Key Wrapping Specification Object Structure
/// The Key Wrapping Specification is a structure that provides information on how a key
/// should be wrapped. It includes the wrapping method, encryption key information,
/// MAC/signature information, attribute names to be included in the wrapped data and
/// encoding options.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyWrappingSpecification {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    pub attribute_names: Option<Vec<String>>,
    pub encoding_option: Option<EncodingOption>,
}

/// Cryptographic Parameters Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CryptographicParameters {
    pub block_cipher_mode: Option<BlockCipherMode>,
    pub padding_method: Option<PaddingMethod>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub key_role_type: Option<KeyRoleType>,
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub random_iv: Option<bool>,
    pub iv_length: Option<i32>,
    pub tag_length: Option<i32>,
    pub fixed_field_length: Option<i32>,
    pub invocation_field_length: Option<i32>,
    pub counter_length: Option<i32>,
    pub initial_counter_value: Option<i32>,
    pub salt_length: Option<i32>,
    pub mask_generator: Option<MaskGenerator>,
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    pub p_source: Option<Vec<u8>>,
    pub trailer_field: Option<i32>,
}

/// 2.1.7.1 Transparent Symmetric Key Structure
/// The Transparent Symmetric Key structure is used to carry the key data for a
/// symmetric key in raw form.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentSymmetricKey {
    pub key: Vec<u8>,
}

/// 2.1.7.2 Transparent DSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDsaPrivateKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub x: Vec<u8>,
}

/// 2.1.7.3 Transparent DSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDsaPublicKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}

/// 2.1.7.4 Transparent RSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentRsaPrivateKey {
    pub modulus: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub public_exponent: Option<Vec<u8>>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub prime_exponent_p: Option<Vec<u8>>,
    pub prime_exponent_q: Option<Vec<u8>>,
    pub crt_coefficient: Option<Vec<u8>>,
    pub recommended_curve: Option<RecommendedCurve>,
}

/// 2.1.7.5 Transparent RSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentRsaPublicKey {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// 2.1.7.6 Transparent DH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDhPrivateKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub j: Option<Vec<u8>>,
    pub x: Vec<u8>,
}

/// 2.1.7.7 Transparent DH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDhPublicKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub j: Option<Vec<u8>>,
    pub y: Vec<u8>,
}

/// 2.1.7.8 Transparent ECDSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdsaPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.9 Transparent ECDSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdsaPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.10 Transparent ECDH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdhPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.11 Transparent ECDH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdhPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.12 Transparent ECMQV Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcmqvPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.13 Transparent ECMQV Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcmqvPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.8 Template-Attribute Structures
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TemplateAttribute {
    pub name: Option<String>,
    pub attributes: Vec<Attribute>,
}

/// 2.1.9 Extension Information Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionInformation {
    pub extension_name: String,
    pub extension_tag: Option<i32>,
    pub extension_type: Option<i32>,
}

/// 2.1.10-23 Additional Structures
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Data(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct DataLength(pub i32);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SignatureData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct MacData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationValue(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct InitIndicator(pub bool);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct FinalIndicator(pub bool);

/// RNG Parameters provides information about random number generation. It contains
/// details about the RNG algorithm, cryptographic algorithms, hash algorithms, DRBG
/// algorithms and associated parameters.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RngParameters {
    pub rng_algorithm: RNGAlgorithm,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub cryptographic_length: Option<i32>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    pub recommended_curve: Option<RecommendedCurve>,
    pub fips186_variation: Option<FIPS186Variation>,
    pub prediction_resistance: Option<bool>,
}

/// Profile Information contains details about supported KMIP profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ProfileInformation {
    pub profile_name: ProfileName,
    pub server_uri: Option<String>,
    pub server_port: Option<i32>,
}

/// Validation Information contains details about the validation of a cryptographic
/// module, including the validation authority, version information and validation
/// profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ValidationInformation {
    pub validation_authority_type: ValidationAuthorityType,
    pub validation_authority_country: Option<String>,
    pub validation_authority_uri: Option<String>,
    pub validation_version_major: Option<i32>,
    pub validation_version_minor: Option<i32>,
    pub validation_type: Option<ValidationType>,
    pub validation_level: Option<i32>,
    pub validation_certificate_identifier: Option<String>,
    pub validation_certificate_uri: Option<String>,
    pub validation_vendor_uri: Option<String>,
    pub validation_profile: Option<String>,
}

/// Capability Information indicates various capabilities supported by a KMIP server.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityInformation {
    pub streaming_capability: bool,
    pub asynchronous_capability: bool,
    pub attestation_capability: bool,
    pub batch_undo_capability: bool,
    pub batch_continue_capability: bool,
    pub unwrap_mode: Option<UnwrapMode>,
    pub destroy_action: Option<DestroyAction>,
    pub shredding_algorithm: Option<ShreddingAlgorithm>,
    pub rng_mode: Option<RNGMode>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedEncryptionAdditionalData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedEncryptionTag(pub Vec<u8>);

/// Derivation Parameters defines the parameters for a key derivation process
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct DerivationParameters {
    /// The type of derivation method to be used
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The initialization vector or nonce if required by the derivation algorithm
    pub initialization_vector: Option<Vec<u8>>,
    /// A value that identifies the derivation process
    pub derivation_data: Option<Vec<u8>>,
    /// The length in bits of the derived data
    pub salt: Option<Vec<u8>>,
    /// Optional iteration count used by the derivation method
    pub iteration_count: Option<i32>,
}
