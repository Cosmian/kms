use cosmian_http_client::{
    HttpClient,
    reexport::reqwest::{Response, StatusCode},
};
// re-export the kmip module as kmip
use cosmian_kms_client_utils::reexport::{
    cosmian_kmip::kmip_0::kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
    cosmian_kmip::kmip_2_1::kmip_operations::{
        Activate, ActivateResponse, AddAttribute, AddAttributeResponse, Certify, CertifyResponse,
        Check, CheckResponse, Create, CreateKeyPair, CreateKeyPairResponse, CreateResponse,
        Decrypt, DecryptResponse, DeleteAttribute, DeleteAttributeResponse, DeriveKey,
        DeriveKeyResponse, Destroy, DestroyResponse, Encrypt, EncryptResponse, Export,
        ExportResponse, Get, GetAttributeList, GetAttributeListResponse, GetAttributes,
        GetAttributesResponse, GetResponse, Hash, HashResponse, Import, ImportResponse, Locate,
        LocateResponse, MAC, MACResponse, MACVerify, MACVerifyResponse, ModifyAttribute,
        ModifyAttributeResponse, Query, QueryResponse, RNGRetrieve, RNGRetrieveResponse, RNGSeed,
        RNGSeedResponse, ReKey, ReKeyKeyPair, ReKeyKeyPairResponse, ReKeyResponse, Register,
        RegisterResponse, Revoke, RevokeResponse, SetAttribute, SetAttributeResponse, Sign,
        SignResponse, SignatureVerify, SignatureVerifyResponse, StatusResponse, Validate,
        ValidateResponse,
    },
    cosmian_kms_access::access::{
        Access, AccessRightsObtainedResponse, ObjectOwnedResponse, SuccessResponse,
        UserAccessResponse,
    },
};
use cosmian_logger::{info, trace};
use serde::Serialize;

use crate::{
    KmsClientConfig,
    cosmian_kmip::{
        kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
        ttlv::{TTLV, from_ttlv, to_ttlv},
    },
    error::{KmsClientError, result::KmsClientResultHelper},
};

/// A struct implementing some of the 50+ operations a KMIP client should implement:
/// <https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip>
#[derive(Clone)]
pub struct KmsClient {
    pub client: HttpClient,
    pub print_json: bool,
    pub config: KmsClientConfig,
}

#[expect(clippy::missing_errors_doc)]
impl KmsClient {
    /// Initialize a KMS REST client.
    ///
    /// Parameters `server_url` and `accept_invalid_certs` from the command line
    /// will override the ones from the configuration file.
    pub fn new() -> Result<Self, KmsClientError> {
        Self::new_with_config(KmsClientConfig::default())
    }

    /// Initialize a KMS REST client.
    ///
    /// Parameters `server_url` and `accept_invalid_certs` from the command line
    /// will override the ones from the configuration file.
    pub fn new_with_config(config: KmsClientConfig) -> Result<Self, KmsClientError> {
        // Instantiate a KMS server REST client with the given configuration
        let kms_rest_client = HttpClient::instantiate(&config.http_config).with_context(|| {
            format!(
                "Unable to instantiate a KMS REST client to server at {}",
                config.http_config.server_url
            )
        })?;

        Ok(Self {
            client: kms_rest_client,
            print_json: config.print_json.unwrap_or_default(),
            config,
        })
    }

    /// This request is used to generate a Certificate object for a public key. This
    /// request supports the certification of a new public key, as well as the
    /// certification of a public key that has already been certified (i.e.,
    /// certificate update). Only a single certificate SHALL be requested at a time.
    ///
    /// The Certificate Request object MAY be omitted, in which case the public key
    /// for which a Certificate object is generated SHALL be specified by its Unique
    /// Identifier only. If the Certificate Request Type and the Certificate Request
    /// objects are omitted from the request, then the Certificate Type SHALL be
    /// specified using the Attributes object.
    ///
    /// The Certificate Request is passed as
    /// a Byte String, which allows multiple certificate request types for X.509
    /// certificates (e.g., PKCS#10, PEM, etc.) to be submitted to the server.
    ///
    /// The generated Certificate object whose Unique Identifier is returned MAY be
    /// obtained by the client via a Get operation in the same batch, using the ID
    /// Placeholder mechanism. For the public key, the server SHALL create a Link
    /// attribute of Link Type Certificate pointing to the generated certificate.
    /// For the generated certificate, the server SHALL create a Link attribute of
    /// Link Type Public Key pointing to the Public Key.
    ///
    /// The server SHALL copy the
    /// Unique Identifier of the generated certificate returned by this operation
    /// into the ID Placeholder variable. If the information in the Certificate
    /// Request conflicts with the attributes specified in the Attributes, then the
    /// information in the Certificate Request takes precedence.
    pub async fn certify(&self, request: Certify) -> Result<CertifyResponse, KmsClientError> {
        self.post_ttlv_2_1::<Certify, CertifyResponse>(&request)
            .await
    }

    /// This operation requests the server to activate a Managed Object currently in Pre-Active state.
    pub async fn activate(&self, request: Activate) -> Result<ActivateResponse, KmsClientError> {
        self.post_ttlv_2_1::<Activate, ActivateResponse>(&request)
            .await
    }

    /// Add a new attribute instance to an object.
    pub async fn add_attribute(
        &self,
        request: AddAttribute,
    ) -> Result<AddAttributeResponse, KmsClientError> {
        self.post_ttlv_2_1::<AddAttribute, AddAttributeResponse>(&request)
            .await
    }

    /// Modify an existing single-valued attribute on an object.
    pub async fn modify_attribute(
        &self,
        request: ModifyAttribute,
    ) -> Result<ModifyAttributeResponse, KmsClientError> {
        self.post_ttlv_2_1::<ModifyAttribute, ModifyAttributeResponse>(&request)
            .await
    }

    /// This operation requests the server to generate a new symmetric key or
    /// generate Secret Data as a Managed Cryptographic Object.
    /// The request contains information about the type of object being created,
    /// and some of the attributes to be assigned to the object (e.g.,
    /// Cryptographic Algorithm, Cryptographic Length, etc.).
    ///
    /// The response contains the Unique Identifier of the created object.
    /// The server SHALL
    /// copy the Unique Identifier returned by this operation into the ID
    /// Placeholder variable.
    pub async fn create(&self, request: Create) -> Result<CreateResponse, KmsClientError> {
        self.post_ttlv_2_1::<Create, CreateResponse>(&request).await
    }

    pub async fn sign(&self, request: Sign) -> Result<SignResponse, KmsClientError> {
        self.post_ttlv_2_1::<Sign, SignResponse>(&request).await
    }

    pub async fn signature_verify(
        &self,
        request: SignatureVerify,
    ) -> Result<SignatureVerifyResponse, KmsClientError> {
        self.post_ttlv_2_1::<SignatureVerify, SignatureVerifyResponse>(&request)
            .await
    }

    /// This operation requests the server to generate a new public/private key
    /// pair and register the two corresponding new Managed Cryptographic Object
    /// The request contains attributes to be assigned to the objects (e.g.,
    /// Cryptographic Algorithm, Cryptographic Length, etc.). Attributes MAY
    /// be specified for both keys at the same time by specifying a Common
    /// Attributes object in the request. Attributes not common to both keys
    /// (e.g., Name, Cryptographic Usage Mask) MAY be specified
    /// using the Private Key Attributes and Public Key Attributes objects in
    /// the request, which take precedence over the Common Attributes object.
    /// For the Private Key, the server SHALL create a Link attribute of Link
    /// Type Public Key pointing to the Public Key. For the Public Key, the
    /// server SHALL create a Link attribute of Link Type Private Key pointing
    /// to the Private Key. The response contains the Unique Identifiers of
    /// both created objects. The ID Placeholder value SHALL be set to the
    /// Unique Identifier of the Private Key
    pub async fn create_key_pair(
        &self,
        request: CreateKeyPair,
    ) -> Result<CreateKeyPairResponse, KmsClientError> {
        self.post_ttlv_2_1::<CreateKeyPair, CreateKeyPairResponse>(&request)
            .await
    }

    /// This operation requests the server to perform a decryption operation on
    /// the provided data using a Managed Cryptographic Object as the key
    /// for the decryption operation.
    ///
    /// The request contains information about the cryptographic parameters
    /// (mode and padding method), the data to be decrypted, and the
    /// IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted
    /// from the request as they can be specified as associated attributes of
    /// the Managed Cryptographic Object.
    ///
    /// The initialization vector/counter/nonce MAY also be omitted from the
    /// request if the algorithm does not use an IV/Counter/Nonce.
    ///
    /// The response contains the Unique Identifier of the Managed Cryptographic
    /// Object used as the key and the result of the decryption operation.
    ///
    /// The success or failure of the operation is indicated by the Result
    /// Status (and if failure the Result Reason) in the response header.
    pub async fn decrypt(&self, request: Decrypt) -> Result<DecryptResponse, KmsClientError> {
        self.post_ttlv_2_1::<Decrypt, DecryptResponse>(&request)
            .await
    }

    /// This operation is used to derive a new key from an existing key using a specified derivation method
    /// such as PBKDF2 or HKDF. The server SHALL perform the derivation function, and then register
    /// the derived object as a new Managed Object, returning the new Unique Identifier for the new object
    /// in the response.
    pub async fn derive_key(
        &self,
        request: DeriveKey,
    ) -> Result<DeriveKeyResponse, KmsClientError> {
        self.post_ttlv_2_1::<DeriveKey, DeriveKeyResponse>(&request)
            .await
    }

    /// This operation is used to indicate to the server that the key material
    /// for the specified Managed Object SHALL be destroyed or rendered
    /// inaccessible. The meta-data for the key material SHALL be retained by
    /// the server.  Objects SHALL only be destroyed if they are in either
    /// Pre-Active or Deactivated state.
    pub async fn destroy(&self, request: Destroy) -> Result<DestroyResponse, KmsClientError> {
        self.post_ttlv_2_1::<Destroy, DestroyResponse>(&request)
            .await
    }

    /// This operation requests the server to perform an encryption operation on
    /// the provided data using a Managed Cryptographic Object as the key
    /// for the encryption operation. The request contains information about
    /// the cryptographic parameters (mode and padding method), the
    /// data to be encrypted, and the IV/Counter/Nonce to use. The cryptographic
    /// parameters MAY be omitted from the request as they can be specified
    /// as associated attributes of the Managed Cryptographic Object.
    /// The IV/Counter/Nonce MAY also be omitted from the request if the
    /// cryptographic parameters indicate that the server shall generate a
    /// Random IV on behalf of the client or the encryption algorithm does not
    /// need an IV/Counter/Nonce. The server does not store or otherwise
    /// manage the IV/Counter/Nonce. If the Managed Cryptographic Object
    /// referenced has a Usage Limits attribute then the server SHALL obtain
    /// an allocation from the current Usage Limits value prior to performing
    /// the encryption operation. If the allocation is unable to be obtained
    /// the operation SHALL return with a result status of Operation Failed
    /// and result reason of Permission Denied.
    ///
    /// The response contains the Unique Identifier of the Managed Cryptographic
    /// Object used as the key and the result of the encryption operation.
    /// The success or failure of the operation is indicated by the Result
    /// Status (and if failure the Result Reason) in the response header.
    pub async fn encrypt(&self, request: Encrypt) -> Result<EncryptResponse, KmsClientError> {
        self.post_ttlv_2_1::<Encrypt, EncryptResponse>(&request)
            .await
    }

    /// This operation requests that the server returns a Managed Object specified by its Unique Identifier,
    /// together with its attributes.
    /// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification
    /// SHALL have the same semantics as for the Get operation.
    /// If the Managed Object has been Destroyed then the key material for the specified managed object
    /// SHALL not be returned in the response.
    /// The server SHALL copy the Unique Identifier returned by this operations
    /// into the ID Placeholder variable.
    pub async fn export(&self, request: Export) -> Result<ExportResponse, KmsClientError> {
        self.post_ttlv_2_1::<Export, ExportResponse>(&request).await
    }

    /// This operation requests that the server returns the Managed Object
    /// specified by its Unique Identifier. Only a single object is
    /// returned. The response contains the Unique Identifier of the object,
    /// along with the object itself, which MAY be wrapped using a wrapping
    /// key as specified in the request. The following key format
    /// capabilities SHALL be assumed by the client; restrictions apply when the
    /// client requests the server to return an object in a particular
    /// format: • If a client registered a key in a given format, the server
    /// SHALL be able to return the key during the Get operation in the same
    /// format that was used when the key was registered. • Any other format
    /// conversion MAY be supported by the server. If Key Format Type is
    /// specified to be PKCS#12 then the response payload shall be a PKCS#12
    /// container as specified by RFC7292. The Unique Identifier shall be
    /// either that of a private key or certificate to be included in the
    /// response. The container shall be protected using the Secret Data object
    /// specified via the private key or certificate's PKCS#12 Password
    /// Link. The current certificate chain shall also be included
    /// as determined by using the private key's Public Key link to get the
    /// corresponding public key (where relevant), and then using that
    /// public key's PKCS#12 Certificate Link to get the base certificate, and
    /// then using each certificate's Ce
    pub async fn get(&self, request: Get) -> Result<GetResponse, KmsClientError> {
        self.post_ttlv_2_1::<Get, GetResponse>(&request).await
    }

    /// This operation requests one or more attributes associated with a Managed
    /// Object. The object is specified by its Unique Identifier, and the
    /// attributes are specified by their name in the request. If a specified
    /// attribute has multiple instances, then all instances are returned. If a
    /// specified attribute does not exist (i.e., has no value), then it
    /// SHALL NOT be present in the returned response. If none of the requested
    /// attributes exist, then the response SHALL consist only of the Unique
    /// Identifier. The same Attribute Reference SHALL NOT be present more
    /// than once in a request. If no Attribute Reference is provided, the
    /// server SHALL return all attributes.
    pub async fn get_attributes(
        &self,
        request: GetAttributes,
    ) -> Result<GetAttributesResponse, KmsClientError> {
        self.post_ttlv_2_1::<GetAttributes, GetAttributesResponse>(&request)
            .await
    }

    /// This operation returns the list of attribute names set on an object.
    pub async fn get_attribute_list(
        &self,
        request: GetAttributeList,
    ) -> Result<GetAttributeListResponse, KmsClientError> {
        self.post_ttlv_2_1::<GetAttributeList, GetAttributeListResponse>(&request)
            .await
    }

    /// This operation requests the server to perform a hash operation on the data provided.
    ///
    /// The request contains information about the cryptographic parameters (hash algorithm)
    /// and the data to be hashed.
    ///
    /// The response contains the result of the hash operation.
    ///
    /// The success or failure of the operation is indicated by the Result Status
    /// (and if failure the Result Reason) in the response header.
    pub async fn hash(&self, request: Hash) -> Result<HashResponse, KmsClientError> {
        self.post_ttlv_2_1::<Hash, HashResponse>(&request).await
    }

    /// Send a Query operation to interrogate server capabilities and metadata.
    pub async fn query(&self, request: Query) -> Result<QueryResponse, KmsClientError> {
        self.post_ttlv_2_1::<Query, QueryResponse>(&request).await
    }

    /// This operation requests the server to either add or modify an attribute. The request contains the Unique Identifier of the Managed Object to which the attribute pertains, along with the attribute and value. If the object did not have any instances of the attribute, one is created. If the object had exactly one instance, then it is modified. If it has more than one instance an error is raised. Read-Only attributes SHALL NOT be added or modified using this operation.
    pub async fn set_attribute(
        &self,
        request: SetAttribute,
    ) -> Result<SetAttributeResponse, KmsClientError> {
        self.post_ttlv_2_1::<SetAttribute, SetAttributeResponse>(&request)
            .await
    }

    /// This operation requests the server to delete an attribute associated with a Managed Object. The request contains the Unique Identifier of the Managed Object whose attribute is to be deleted, the Current Attribute of the attribute. Attributes that are always REQUIRED to have a value SHALL never be deleted by this operation. Attempting to delete a non-existent attribute or specifying an Current Attribute for which there exists no attribute value SHALL result in an error. If no Current Attribute is specified in the request, and an Attribute Reference is specified, then all instances of the specified attribute SHALL be deleted.
    pub async fn delete_attribute(
        &self,
        request: DeleteAttribute,
    ) -> Result<DeleteAttributeResponse, KmsClientError> {
        self.post_ttlv_2_1::<DeleteAttribute, DeleteAttributeResponse>(&request)
            .await
    }

    /// This operation requests the server to Import a Managed Object specified
    /// by its Unique Identifier. The request specifies the object being
    /// imported and all the attributes to be assigned to the object. The
    /// attribute rules for each attribute for "Initially set by" and "When
    /// implicitly set" SHALL NOT be enforced as all attributes MUST be set
    /// to the supplied values rather than any server generated values.
    /// The response contains the Unique Identifier provided in the request or
    /// assigned by the server. The server SHALL copy the Unique Identifier
    /// returned by this operations into the ID Placeholder variable.
    pub async fn import(&self, request: Import) -> Result<ImportResponse, KmsClientError> {
        self.post_ttlv_2_1::<Import, ImportResponse>(&request).await
    }

    /// This operation requests that the server search for one or more Managed
    /// Objects, depending on the attributes specified in the request. All
    /// attributes are allowed to be used. The request MAY contain a Maximum
    /// Items field, which specifies the maximum number of objects to be
    /// returned. If the Maximum Items field is omitted, then the server MAY
    /// return all objects matched, or MAY impose an internal maximum limit due
    /// to resource limitations.
    ///
    /// The request MAY contain an Offset Items field, which specifies the
    /// number of objects to skip that satisfy the identification criteria
    /// specified in the request. An Offset Items field of 0 is the same as
    /// omitting the Offset Items field. If both Offset Items and Maximum Items
    /// are specified in the request, the server skips Offset Items objects and
    /// returns up to Maximum Items objects.
    ///
    /// If more than one object satisfies the identification criteria specified
    /// in the request, then the response MAY contain Unique Identifiers for
    /// multiple Managed Objects. Responses containing Unique Identifiers for
    /// multiple objects SHALL be returned in descending order of object
    /// creation (most recently created object first).  Returned objects SHALL
    /// match all of the attributes in the request. If no objects match, then an
    /// empty response payload is returned. If no attribute is specified in the
    /// request, any object SHALL be deemed to match the Locate request. The
    /// response MAY include Located Items which is the count of all objects
    /// that satisfy the identification criteria.
    ///
    /// The server returns a list of Unique Identifiers of the found objects,
    /// which then MAY be retrieved using the Get operation. If the objects are
    /// archived, then the Recover and Get operations are REQUIRED to be used to
    /// obtain those objects. If a single Unique Identifier is returned to the
    /// client, then the server SHALL copy the Unique Identifier returned by
    /// this operation into the ID Placeholder variable.  If the Locate
    /// operation matches more than one object, and the Maximum Items value is
    /// omitted in the request, or is set to a value larger than one, then the
    /// server SHALL empty the ID Placeholder, causing any subsequent operations
    /// that are batched with the Locate, and which do not specify a Unique
    /// Identifier explicitly, to fail. This ensures that these batched
    /// operations SHALL proceed only if a single object is returned by Locate.
    ///
    /// The Date attributes in the Locate request (e.g., Initial Date,
    /// Activation Date, etc.) are used to specify a time or a time range for
    /// the search. If a single instance of a given Date attribute is used in
    /// the request (e.g., the Activation Date), then objects with the same Date
    /// attribute are considered to be matching candidate objects. If two
    /// instances of the same Date attribute are used (i.e., with two different
    /// values specifying a range), then objects for which the Date attribute is
    /// inside or at a limit of the range are considered to be matching
    /// candidate objects. If a Date attribute is set to its largest possible
    /// value, then it is equivalent to an undefined attribute. The KMIP Usage
    /// Guide [KMIP-UG] provides examples.
    ///
    /// When the Cryptographic Usage Mask attribute is specified in the request,
    /// candidate objects are compared against this field via an operation that
    /// consists of a logical AND of the requested mask with the mask in the
    /// candidate object, and then a comparison of the resulting value with the
    /// requested mask. For example, if the request contains a mask value of
    /// 10001100010000, and a candidate object mask contains 10000100010000,
    /// then the logical AND of the two masks is 10000100010000, which is
    /// compared against the mask value in the request (10001100010000) and the
    /// match fails. This means that a matching candidate object has all of the
    /// bits set in its mask that are set in the requested mask, but MAY have
    /// additional bits set.
    ///
    /// When the Usage Limits attribute is specified in the request, matching
    /// candidate objects SHALL have a Usage Limits Count and Usage Limits Total
    /// equal to or larger than the values specified in the request.
    ///
    /// When an attribute that is defined as a structure is specified, all of
    /// the structure fields are not REQUIRED to be specified. For instance, for
    /// the Link attribute, if the Linked Object Identifier value is specified
    /// without the Link Type value, then matching candidate objects have the
    /// Linked Object Identifier as specified, irrespective of their Link Type.
    ///
    /// When the Object Group attribute and the Object Group Member flag are
    /// specified in the request, and the value specified for Object Group
    /// Member is 'Group Member Fresh', matching candidate objects SHALL be
    /// fresh objects from the object group. If there are no more fresh objects
    /// in the group, the server MAY choose to generate a new object on-the-fly,
    /// based on server policy. If the value specified for Object Group Member
    /// is 'Group Member Default', the server locates the default object as
    /// defined by server policy.
    ///
    /// The Storage Status Mask field is used to indicate whether on-line
    /// objects (not archived or destroyed), archived objects, destroyed objects
    /// or any combination of the above are to be searched.The server SHALL NOT
    /// return unique identifiers for objects that are destroyed unless the
    /// Storage Status Mask field includes the Destroyed Storage indicator. The
    /// server SHALL NOT return unique identifiers for objects that are archived
    /// unless the Storage Status Mask field includes the Archived Storage
    /// indicator.
    pub async fn locate(&self, request: Locate) -> Result<LocateResponse, KmsClientError> {
        self.post_ttlv_2_1::<Locate, LocateResponse>(&request).await
    }

    /// This operation requests the server to perform message authentication code (MAC)
    /// operation on the provided data using a Managed Cryptographic Object as the key
    /// for the MAC operation.
    ///
    /// The request contains information about the cryptographic parameters (cryptographic algorithm)
    /// and the data to be `MACed`. The cryptographic parameters MAY be omitted from the request as they can
    /// be specified as associated attributes of the Managed Cryptographic Object.
    ///
    /// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and
    /// the result of the MAC operation.
    ///
    /// The success or failure of the operation is indicated by the Result Status (and if failure the Result
    /// Reason) in the response header.
    pub async fn mac(&self, request: MAC) -> Result<MACResponse, KmsClientError> {
        self.post_ttlv_2_1::<MAC, MACResponse>(&request).await
    }

    /// Verify a Message Authentication Code (MAC) against provided data.
    pub async fn mac_verify(
        &self,
        request: MACVerify,
    ) -> Result<MACVerifyResponse, KmsClientError> {
        self.post_ttlv_2_1::<MACVerify, MACVerifyResponse>(&request)
            .await
    }

    // This request is used to generate a replacement key pair for an existing
    // public/private key pair.  It is analogous to the Create Key Pair operation,
    // except that attributes of the replacement key pair are copied from the
    // existing key pair, with the exception of the attributes listed in Re-key Key
    // Pair Attribute Requirements tor.
    //
    // As the replacement of the key pair takes over the name attribute for the
    // existing public/private key pair, Re-key Key Pair SHOULD only be performed
    // once on a given key pair.
    //
    // For both the existing public key and private key, the server SHALL create a
    // Link attribute of Link Type Replacement Key pointing to the replacement
    // public and private key, respectively. For both the replacement public and
    // private key, the server SHALL create a Link attribute of Link Type Replaced
    // Key pointing to the existing public and private key, respectively.
    //
    // The server SHALL copy the Private Key Unique Identifier of the replacement
    // private key returned by this operation into the ID Placeholder variable.
    //
    // An Offset MAY be used to indicate the difference between the Initial Date and
    // the Activation Date of the replacement key pair. If no Offset is specified,
    // the Activation Date and Deactivation Date values are copied from the existing
    // key pair. If Offset is set and dates exist for the existing key pair, then
    // the dates of the replacement key pair SHALL be set based on the dates of the
    // existing key pair as follows
    pub async fn rekey_keypair(
        &self,
        request: ReKeyKeyPair,
    ) -> Result<ReKeyKeyPairResponse, KmsClientError> {
        self.post_ttlv_2_1::<ReKeyKeyPair, ReKeyKeyPairResponse>(&request)
            .await
    }

    /// This request is used to generate a replacement key for an existing symmetric key. It is analogous to the Create operation, except that attributes of the replacement key are copied from the existing key, with the exception of the attributes listed in Re-key Attribute Requirements.
    ///
    /// As the replacement key takes over the name attribute of the existing key, Re-key SHOULD only be performed once on a given key.
    ///
    /// The server SHALL copy the Unique Identifier of the replacement key returned by this operation into the ID Placeholder variable.
    ///
    /// For the existing key, the server SHALL create a Link attribute of Link Type Replacement Object pointing to the replacement key. For the replacement key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing key.
    ///
    /// An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key. If no Offset is specified, the Activation Date, Process Start Date, Protect Stop Date and Deactivation Date values are copied from the existing key.
    pub async fn rekey(&self, request: ReKey) -> Result<ReKeyResponse, KmsClientError> {
        self.post_ttlv_2_1::<ReKey, ReKeyResponse>(&request).await
    }

    /// This operation requests the server to revoke a Managed Cryptographic
    /// Object or an Opaque Object. The request contains a reason for the
    /// revocation (e.g., "key compromise", "cessation of operation", etc.). The
    /// operation has one of two effects. If the revocation reason is "key
    /// compromise" or "CA compromise", then the object is placed into the
    /// "compromised" state; the Date is set to the current date and time; and
    /// the Compromise Occurrence Date is set to the value (if provided) in the
    /// Revoke request and if a value is not provided in the Revoke request then
    /// Compromise Occurrence Date SHOULD be set to the Initial Date for the
    /// object. If the revocation reason is neither "key compromise" nor "CA
    /// compromise", the object is placed into the "deactivated" state, and the
    /// Deactivation Date is set to the current date and time.
    pub async fn revoke(&self, request: Revoke) -> Result<RevokeResponse, KmsClientError> {
        self.post_ttlv_2_1::<Revoke, RevokeResponse>(&request).await
    }

    /// This operation requests the server to validate a Managed Certificate Chain.
    pub async fn validate(&self, request: Validate) -> Result<ValidateResponse, KmsClientError> {
        self.post_ttlv_2_1::<Validate, ValidateResponse>(&request)
            .await
    }

    /// Register an existing object (key/cert/opaque/secret data) with the server.
    pub async fn register(&self, request: Register) -> Result<RegisterResponse, KmsClientError> {
        self.post_ttlv_2_1::<Register, RegisterResponse>(&request)
            .await
    }

    /// Compute a signature over provided data with a Managed Object key.
    pub async fn sign(&self, request: Sign) -> Result<SignResponse, KmsClientError> {
        self.post_ttlv_2_1::<Sign, SignResponse>(&request).await
    }

    /// Verify a signature over provided data.
    pub async fn signature_verify(
        &self,
        request: SignatureVerify,
    ) -> Result<SignatureVerifyResponse, KmsClientError> {
        self.post_ttlv_2_1::<SignatureVerify, SignatureVerifyResponse>(&request)
            .await
    }

    /// Retrieve random bytes from server's RNG.
    pub async fn rng_retrieve(
        &self,
        request: RNGRetrieve,
    ) -> Result<RNGRetrieveResponse, KmsClientError> {
        self.post_ttlv_2_1::<RNGRetrieve, RNGRetrieveResponse>(&request)
            .await
    }

    /// Seed the server's RNG with provided data.
    pub async fn rng_seed(&self, request: RNGSeed) -> Result<RNGSeedResponse, KmsClientError> {
        self.post_ttlv_2_1::<RNGSeed, RNGSeedResponse>(&request)
            .await
    }

    /// Discover protocol versions supported by the server.
    pub async fn discover_versions(
        &self,
        request: DiscoverVersions,
    ) -> Result<DiscoverVersionsResponse, KmsClientError> {
        self.post_ttlv_2_1::<DiscoverVersions, DiscoverVersionsResponse>(&request)
            .await
    }

    /// Check if a Managed Object may be used under server policy with given parameters.
    pub async fn check(&self, request: Check) -> Result<CheckResponse, KmsClientError> {
        self.post_ttlv_2_1::<Check, CheckResponse>(&request).await
    }

    /// This operation requests the server to send a message, which is a list of operations,
    /// to the server.
    /// The messages in the protocol consist of a message header, one or more batch items
    /// (which contain OPTIONAL message payloads), and OPTIONAL message extensions.
    /// The message headers contain fields whose presence is determined
    /// by the protocol features used (e.g., asynchronous responses).
    /// The field contents are also determined by whether the message is a request or a response.
    /// The message payload is determined by the specific operation being requested
    /// or to which is being replied.
    pub async fn message(
        &self,
        request: RequestMessage,
    ) -> Result<ResponseMessage, KmsClientError> {
        // This uses the /kmip endpoint, which is the default endpoint for the KMS server
        self.post_message(&request).await
    }

    /// This operation requests the server to grant an access on an object to a user
    /// The user could be unknown from the database.
    /// The object uid must be known from the database.
    /// If the user already has access, nothing is done. No error is returned.
    /// The user (owner) can't grant access to himself/herself.
    pub async fn grant_access(&self, access: Access) -> Result<SuccessResponse, KmsClientError> {
        self.post_no_ttlv("/access/grant", Some(&access)).await
    }

    /// This operation requests the server to revoke an access on an object to a user
    /// The user could be unknown from the database.
    /// The object uid must be known from the database.
    /// If the user already has no access, nothing is done. No error is returned.
    pub async fn revoke_access(&self, access: Access) -> Result<SuccessResponse, KmsClientError> {
        self.post_no_ttlv("/access/revoke", Some(&access)).await
    }

    /// This operation requests the server to list all the granted access on a object
    pub async fn list_access(&self, uid: &str) -> Result<Vec<UserAccessResponse>, KmsClientError> {
        self.get_no_ttlv(&format!("/access/list/{uid}"), None::<&()>)
            .await
    }

    /// This operation requests the server to list all the objects owned by the current user.
    /// i.e. the objects for which the user has full access
    pub async fn list_owned_objects(&self) -> Result<Vec<ObjectOwnedResponse>, KmsClientError> {
        self.get_no_ttlv("/access/owned", None::<&()>).await
    }

    /// This operation requests the server to list all the object for
    /// which access rights have been obtained for the current user.
    pub async fn list_access_rights_obtained(
        &self,
    ) -> Result<Vec<AccessRightsObtainedResponse>, KmsClientError> {
        self.get_no_ttlv("/access/obtained", None::<&()>).await
    }

    /// This operation requests the version of the server
    pub async fn version(&self) -> Result<String, KmsClientError> {
        self.get_no_ttlv("/version", None::<&()>).await
    }

    /// This operation requests `google_cse` status of the server
    pub async fn google_cse_status(&self) -> Result<StatusResponse, KmsClientError> {
        self.get_no_ttlv("/google_cse/status", None::<&()>).await
    }

    pub async fn get_no_ttlv<R, O>(
        &self,
        endpoint: &str,
        data: Option<&O>,
    ) -> Result<R, KmsClientError>
    where
        R: serde::de::DeserializeOwned + Sized + 'static,
        O: Serialize + Sync,
    {
        let server_url = format!("{}{endpoint}", self.client.server_url);
        info!("GET {server_url}");
        let response = match data {
            Some(d) => self.client.client.get(server_url).query(d).send().await?,
            None => self.client.client.get(server_url).send().await?,
        };

        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<R>().await?);
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(KmsClientError::Unauthorized(p));
        }
        Err(KmsClientError::RequestFailed(p))
    }

    pub async fn delete_no_ttlv<O, R>(&self, endpoint: &str, data: &O) -> Result<R, KmsClientError>
    where
        O: Serialize + Sync,
        R: serde::de::DeserializeOwned + Sized + 'static,
    {
        let server_url = format!("{}{endpoint}", self.client.server_url);
        let response = self
            .client
            .client
            .delete(server_url)
            .json(data)
            .send()
            .await?;

        let status_code = response.status();
        if status_code.is_success() {
            return Ok(response.json::<R>().await?);
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(KmsClientError::Unauthorized(p));
        }
        Err(KmsClientError::RequestFailed(p))
    }

    pub async fn post_no_ttlv<O, R>(
        &self,
        endpoint: &str,
        data: Option<&O>,
    ) -> Result<R, KmsClientError>
    where
        O: Serialize + Sync,
        R: serde::de::DeserializeOwned + Sized + Serialize + 'static,
    {
        let server_url = format!("{}{endpoint}", self.client.server_url);
        let response = match data {
            Some(d) => {
                trace!(
                    "==>\n{}",
                    serde_json::to_string_pretty(&d).unwrap_or_else(|_| "[N/A]".to_owned())
                );
                self.client.client.post(server_url).json(d).send().await?
            }
            None => self.client.client.post(server_url).send().await?,
        };

        let status_code = response.status();
        if status_code.is_success() {
            let response = response.json::<R>().await?;
            trace!(
                "<==\n{}",
                serde_json::to_string_pretty(&response).unwrap_or_else(|_| "[N/A]".to_owned())
            );
            return Ok(response);
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(KmsClientError::Unauthorized(p));
        }
        Err(KmsClientError::RequestFailed(p))
    }

    #[expect(clippy::print_stdout)]
    pub async fn post_ttlv_2_1<O, R>(&self, kmip_request: &O) -> Result<R, KmsClientError>
    where
        O: Serialize + Sync,
        R: serde::de::DeserializeOwned + Sized + 'static,
    {
        let endpoint = "/kmip/2_1";
        let server_url = format!("{}{endpoint}", self.client.server_url);
        let mut request = self.client.client.post(&server_url);
        let ttlv = to_ttlv(kmip_request)?;
        if self.print_json {
            println!(
                "\nKMIP Request ==>\n{}",
                serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
            );
        }
        trace!(
            "==>\n{}",
            serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
        );
        request = request.json(&ttlv);

        let response = request.send().await?;
        let status_code = response.status();
        if status_code.is_success() {
            let ttlv = response.json::<TTLV>().await?;
            if self.print_json {
                println!(
                    "\nKMIP Response <==\n{}\n",
                    serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
                );
            }
            trace!(
                "<==\n{}",
                serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
            );
            return from_ttlv(ttlv).map_err(|e| KmsClientError::ResponseFailed(e.to_string()));
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(KmsClientError::Unauthorized(p));
        }
        Err(KmsClientError::RequestFailed(p))
    }

    #[expect(clippy::print_stdout)]
    pub async fn post_message(
        &self,
        request_message: &RequestMessage,
    ) -> Result<ResponseMessage, KmsClientError> {
        let endpoint = "/kmip";
        let server_url = format!("{}{endpoint}", self.client.server_url);
        let mut request = self.client.client.post(&server_url);
        let ttlv = to_ttlv(request_message)?;
        if self.print_json {
            println!(
                "\nKMIP Request ==>\n{}",
                serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
            );
        }
        trace!(
            "==>\n{}",
            serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
        );
        request = request.json(&ttlv);

        let response = request.send().await?;
        let status_code = response.status();
        if status_code.is_success() {
            let ttlv = response.json::<TTLV>().await?;
            if self.print_json {
                println!(
                    "\nKMIP Response <==\n{}\n",
                    serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
                );
            }
            trace!(
                "<==\n{}",
                serde_json::to_string_pretty(&ttlv).unwrap_or_else(|_| "[N/A]".to_owned())
            );
            return from_ttlv(ttlv).map_err(|e| KmsClientError::ResponseFailed(e.to_string()));
        }

        // process error
        let p = handle_error(endpoint, response).await?;
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(KmsClientError::Unauthorized(p));
        }
        Err(KmsClientError::RequestFailed(p))
    }
}

/// Some errors are returned by the Middleware without going through our own error manager.
/// In that case, we make the error clearer here for the client.
async fn handle_error(endpoint: &str, response: Response) -> Result<String, KmsClientError> {
    trace!("Error response received on {endpoint}: Response: {response:?}");
    let status = response.status();
    let text = response.text().await?;

    Ok(format!(
        "{}: {}",
        endpoint,
        if text.is_empty() {
            match status {
                StatusCode::NOT_FOUND => "KMS server endpoint does not exist".to_owned(),
                StatusCode::UNAUTHORIZED => "Bad authorization token".to_owned(),
                _ => format!("{status} {text}"),
            }
        } else {
            text
        }
    ))
}
