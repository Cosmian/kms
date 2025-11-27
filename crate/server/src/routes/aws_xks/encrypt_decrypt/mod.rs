mod decrypt_;
mod encrypt_;
pub(crate) use decrypt_::decrypt;
pub(crate) use encrypt_::encrypt;
use serde::{Deserialize, Serialize};

/// Request Payload Parameters: The HTTP body of the request contains the requestMetadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) struct RequestMetadata {
    /// This is the ARN of the principal that invoked KMS Decrypt (see aws:PrincipalArn).
    /// When the caller is another AWS service, this field will contain either
    /// the service principal ending in amazonaws.com, such as ec2.amazonaws.com or
    /// “AWS Internal”. This field is REQUIRED.
    pub awsPrincipalArn: String,
    /// This field is OPTIONAL. It is present if and only if the KMS API request was made using
    /// a VPC endpoint.
    /// When present, this field indicates the VPC where the request originated (see aws:SourceVpc).
    pub awsSourceVpc: Option<String>,
    /// This field is OPTIONAL. It is present if and only if the KMS API request was made using
    /// a VPC endpoint.
    /// When present, this field indicates the VPC endpoint used for the request (see aws:SourceVpce)
    pub awsSourceVpce: Option<String>,
    /// This is the ARN of the KMS Key on which the Decrypt, `ReDecrypt`, `GenerateDataKey`
    /// or `GenerateDataKeyWithoutPlaintext` API was invoked. This field is REQUIRED.
    pub kmsKeyArn: String,
    /// This is the KMS API call that resulted in the XKS Proxy API request,
    /// e.g. `CreateKey` can result in a `GetKeyMetadata` call. This field is REQUIRED.
    /// The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation
    /// other than those listed for this API call.
    /// In the future, KMS may introduce a new API that can be satisfied
    /// by calling one of the XKS APIs listed in this document.
    /// For proxies that implement secondary authorization,
    /// it is acceptable for XKS API requests made as part of the new KMS API to fail authorization.
    /// It is easier for a customer to update their XKS Proxy authorization policy
    /// than to update their XKS Proxy software.
    pub kmsOperation: String,
    /// This is the requestId of the call made to KMS which is visible in AWS `CloudTrail`.
    /// The XKS proxy SHOULD log this field to allow a customer
    /// to correlate AWS `CloudTrail` entries with log entries in the XKS Proxy.
    /// This field typically follows the format for UUIDs
    /// but the XKS Proxy MUST treat this as an opaque string
    /// and MUST NOT perform any validation on its structure.
    /// This field is REQUIRED.
    pub kmsRequestId: String,
    /// This field is OPTIONAL. If present, it indicates the AWS service that called the KMS API
    /// on behalf of a customer (see kms:ViaService)
    pub kmsViaService: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub(crate) enum EncryptionAlgorithm {
    AES_GCM,
}

/// Ciphertext Data Integrity Value Algorithm
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub(crate) enum CdivAlgorithm {
    SHA_256,
}
