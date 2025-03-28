use std::{
    fmt,
    fmt::{Display, Formatter},
};

use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use tracing::trace;

use crate::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_objects::ObjectType,
        kmip_types::{
            AlternativeName, ApplicationSpecificInformation, CertificateAttributes,
            CertificateType, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicParameters, CryptographicUsageMask, DigitalSignatureAlgorithm,
            KeyFormatType, KeyValueLocationType, Link, LinkType, LinkedObjectIdentifier, Name,
            NistKeyType, ObjectGroupMember, OpaqueDataType, ProtectionLevel,
            ProtectionStorageMasks, RandomNumberGenerator, RevocationReason, State,
            UniqueIdentifier, UsageLimits, VendorAttribute, X509CertificateIdentifier,
            VENDOR_ATTR_AAD,
        },
    },
    KmipError,
};

/// The following subsections describe the attributes that are associated with
/// Managed Objects. Attributes that an object MAY have multiple instances of
/// are referred to as multi-instance attributes. All instances of an attribute
/// SHOULD have a different value. Similarly, attributes which an object SHALL
/// only have at most one instance of are referred to as single-instance
/// attributes. Attributes are able to be obtained by a client from the server
/// using the Get Attribute operation. Some attributes are able to be set by the
/// Add Attribute operation or updated by the Modify Attribute operation, and
/// some are able to be deleted by the Delete Attribute operation if they no
/// longer apply to the Managed Object. Read-only attributes are attributes that
/// SHALL NOT be modified by either server or client, and that SHALL NOT be
/// deleted by a client.
/// When attributes are returned by the server (e.g., via a Get Attributes
/// operation), the attribute value returned SHALL NOT differ for different
/// clients unless specifically noted against each attribute. The first table in
/// each subsection contains the attribute name in the first row. This name is
/// the canonical name used when managing attributes using the Get Attributes,
/// Get Attribute List, Add Attribute, Modify Attribute, and Delete Attribute
/// operations. A server SHALL NOT delete attributes without receiving a request
/// from a client until the object is destroyed. After an object is destroyed,
/// the server MAY retain all, some or none of the object attributes,
/// depending on the object type and server policy.
// TODO: there are 56 attributes in the specs. Only a handful are implemented here
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Attributes {
    /// The Activation Date attribute contains the date and time when the
    /// Managed Object MAY begin to be used. This time corresponds to state
    /// transition. The object SHALL NOT be used for any cryptographic
    /// purpose before the Activation Date has been reached. Once the state
    /// transition from Pre-Active has occurred, then this attribute SHALL
    /// NOT be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_date: Option<i64>, // epoch millis

    /// The Alternative Name attribute is a variable length text string that is associated
    /// with the unique identifier of the object. It may be used as an alternative name to
    /// identify the object, instead of using its unique identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_name: Option<AlternativeName>,

    /// The Always Sensitive attribute is a Boolean that indicates whether the key material
    /// of a Symmetric Key, Private Key, or Secret Data object has always been considered
    /// sensitive. This attribute SHOULD only be used for Managed Objects with the Sensitive
    /// attribute set to True.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_sensitive: Option<bool>,

    /// The Application Specific Information attribute is a structure used to store data specific
    /// to the application(s) using the Managed Object. It consists of the following fields:
    /// - Application Namespace - Text String
    /// - Application Data - Text String
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_specific_information: Option<ApplicationSpecificInformation>,

    /// The Archive Date attribute contains the date and time when the Managed Object was
    /// transferred to the Archive state in the Object States table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_date: Option<i64>,

    /// The Attribute Index attribute is used to identify distinct instances of multi-instance attributes.
    /// The combination of the attribute name and the Attribute Index SHALL be unique
    /// within an instance of a managed object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_index: Option<i32>,

    /// The Certificate Attributes are the various items included in a certificate.
    /// The following list is based on RFC2253.
    #[allow(clippy::struct_field_names)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_attributes: Option<CertificateAttributes>,

    /// The Certificate Type attribute is a type of certificate (e.g., X.509).
    /// The Certificate Type value SHALL be set by the server when the certificate
    /// is created or registered and then SHALL NOT be changed or deleted
    /// before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<CertificateType>,

    /// The Certificate Length attribute is the length in bytes of the Certificate object.
    /// The Certificate Length SHALL be set by the server when the object is created or registered,
    /// and then SHALL NOT be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_length: Option<i32>,

    /// The Comment attribute is a text string that MAY be used to provide additional
    /// information about the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The Compromise Date attribute contains the date and time when the Managed Object
    /// entered the Compromised state in the Object States table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_date: Option<i64>,

    /// The Compromise Occurrence Date attribute contains the date and time when the
    /// Managed Object was first believed to be compromised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_occurrence_date: Option<i64>,

    /// The Contact Information attribute is a text string that MAY be used to identify
    /// or provide information about the Contact for the Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_information: Option<String>,

    /// The Critical attribute is a Boolean value that indicates whether the Cryptographic
    /// Usage Mask attribute should be always provided for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<bool>,

    /// The Cryptographic Algorithm of an object. The Cryptographic Algorithm of
    /// a Certificate object identifies the algorithm for the public key
    /// contained within the Certificate. The digital signature algorithm used
    /// to sign the Certificate is identified in the Digital Signature
    /// Algorithm attribute. This attribute SHALL be set by the server when
    /// the object is created or registered and then SHALL NOT be changed or
    /// deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// The Cryptographic Domain Parameters attribute is a structure that
    /// contains fields that MAY need to be specified in the Create Key Pair
    /// Request Payload. Specific fields MAY only pertain to certain types
    /// of Managed Cryptographic Objects. The domain parameter Q-length
    /// corresponds to the bit length of parameter Q (refer to
    /// [RFC7778](https://www.rfc-editor.org/rfc/rfc7778.txt),
    /// [SEC2](https://www.secg.org/sec2-v2.pdf) and
    /// [SP800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_domain_parameters: Option<CryptographicDomainParameters>,

    /// For keys, Cryptographic Length is the length in bits of the clear-text
    /// cryptographic key material of the Managed Cryptographic Object. For
    /// certificates, Cryptographic Length is the length in bits of the public
    /// key contained within the Certificate. This attribute SHALL be set by the
    /// server when the object is created or registered, and then SHALL NOT
    /// be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,

    /// See `CryptographicParameters`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    /// The Cryptographic Usage Mask attribute defines the cryptographic usage
    /// of a key. This is a bit mask that indicates to the client which
    /// cryptographic functions MAY be performed using the key, and which ones
    /// SHALL NOT be performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_usage_mask: Option<CryptographicUsageMask>,

    /// The Deactivation Date attribute contains the date and time when the
    /// Managed Object SHALL NOT be used for any purpose, except for deletion,
    /// destruction, or re-activation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivation_date: Option<i64>,

    /// The Description attribute is a string containing a description of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The Destroy Date attribute contains the date and time when the Managed Object
    /// was destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_date: Option<i64>,

    /// The Digital Signature Algorithm attribute specifies the digital signature algorithm
    /// that is used with the signing key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,

    /// The Extractable attribute is a Boolean that indicates whether the Managed Object
    /// may be extracted from the cryptographic device on which it is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extractable: Option<bool>,

    /// The Fresh attribute indicates if the key value has remained unchanged
    /// since its initial generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,

    /// The Initial Date attribute contains the date and time when the Managed Object
    /// was first created or registered at the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_date: Option<i64>,

    /// 4.26 The Key Format Type attribute is a required attribute of a
    /// Cryptographic Object. It is set by the server, but a particular Key
    /// Format Type MAY be requested by the client if the cryptographic material
    /// is produced by the server (i.e., Create, Create Key Pair, Create
    /// Split Key, Re-key, Re-key Key Pair, Derive Key) on the
    /// client's behalf. The server SHALL comply with the client's requested
    /// format or SHALL fail the request. When the server calculates a
    /// Digest for the object, it SHALL compute the digest on the data in the
    /// assigned Key Format Type, as well as a digest in the default KMIP Key
    /// Format Type for that type of key and the algorithm requested (if a
    /// non-default value is specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,

    // The Key Value Location attribute identifies whether the key value is stored
    /// on the KMIP server or stored on an external repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_value_location: Option<KeyValueLocationType>,

    /// The Key Value Present attribute is a Boolean that indicates whether a key value
    /// is present in the key block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_value_present: Option<bool>,

    /// The Last Change Date attribute contains the date and time of the last change
    /// to the Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_change_date: Option<i64>,

    /// The Lease Time attribute is the length of time in seconds that the object MAY
    /// be retained by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<i64>,

    /// The Link attribute is a structure used to create a link from one Managed
    /// Cryptographic Object to another, closely related target Managed
    /// Cryptographic Object. The link has a type, and the allowed types differ,
    /// depending on the Object Type of the Managed Cryptographic Object, as
    /// listed below. The Linked Object Identifier identifies the target
    /// Managed Cryptographic Object by its Unique Identifier. The link contains
    /// information about the association between the Managed Objects (e.g., the
    /// private key corresponding to a public key; the parent certificate
    /// for a certificate in a chain; or for a derived symmetric key, the base
    /// key from which it was derived).
    /// The Link attribute SHOULD be present for private keys and public keys
    /// for which a certificate chain is stored by the server, and for
    /// certificates in a certificate chain. Note that it is possible for a
    /// Managed Object to have multiple instances of the Link attribute (e.g., a
    /// Private Key has links to the associated certificate, as well as the
    /// associated public key; a Certificate object has links to both the
    /// public key and to the certificate of the certification authority (CA)
    /// that signed the certificate).
    /// It is also possible that a Managed Object does not have links to
    /// associated cryptographic objects. This MAY occur in cases where the
    /// associated key material is not available to the server or client (e.g.,
    /// the registration of a CA Signer certificate with a server, where the
    /// corresponding private key is held in a different manner)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<Vec<Link>>,

    /// The Name attribute is a structure used to identify and locate the object.
    /// The Name attribute MUST contain the Name Value. The Name Value member is
    /// either a Text String or Enumeration.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Vec<Name>>,

    /// The Never Extractable attribute is a Boolean that indicates whether the key material
    /// of a Symmetric Key, Private Key, or Secret Data object has never been extractable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub never_extractable: Option<bool>,

    /// The NIST Key Type attribute is used to identify the key type used with the
    /// NIST SP 800-56 and SP 800-108 operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_key_type: Option<NistKeyType>,

    /// The Object Group attribute is a Text String that MAY be used to identify a group
    /// of objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_group: Option<String>,

    /// The Object Group Member attribute is an enumeration that indicates how the
    /// object is a member of an object group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_group_member: Option<ObjectGroupMember>,

    /// The Object Typeof a Managed Object (e.g., public key, private key,
    /// symmetric key, etc.) SHALL be set by the server when the object is
    /// created or registered and then SHALL NOT be changed or deleted before
    /// the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<ObjectType>,

    /// The Opaque Data Type attribute is an enumeration that indicates the type of opaque
    /// data contained in the value of the opaque data attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_data_type: Option<OpaqueDataType>,

    /// The Original Creation Date attribute contains the date and time the object
    /// was created by the client that first created it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_creation_date: Option<i64>,

    /// The PKCS#12 Friendly Name attribute is a string used to identify the key
    /// material stored within a PKCS#12 object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs_12_friendly_name: Option<String>,

    /// The Process Start Date attribute is the date and time that a managed object
    /// is considered to enter the processing state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_start_date: Option<i64>,

    /// The Protect Stop Date attribute is the date and time that a managed object
    /// is considered to enter the protected state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_stop_date: Option<i64>,

    /// The Protection Level attribute indicates the level of protection required for a object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<ProtectionLevel>,

    /// The Protection Period attribute is the length of time in seconds that the
    /// object MAY be protected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_period: Option<i64>,

    /// The Protection Storage Masks attribute contains a list of masks that define
    /// storage protections required for an object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_storage_masks: Option<ProtectionStorageMasks>,

    /// The Quantum Safe attribute is a Boolean that indicates whether the key is
    /// quantum safe or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_safe: Option<bool>,

    /// The Random Number Generator attribute is a structure that contains the details
    /// of the random number generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_number_generator: Option<RandomNumberGenerator>,

    /// The Revocation Reason attribute is a structure used to indicate why the
    /// Managed Object was revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,

    /// The Rotate Date attribute specifies the date and time for the last rotation
    /// of a Managed Cryptographic Object. The Rotate Date attribute SHALL be set by
    /// the server when the Rotate operation successfully completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_date: Option<i64>,

    /// The Rotate Generation attribute specifies the generation of the last rotation
    /// of a Managed Cryptographic Object. The Rotate Generation attribute SHALL be set
    /// by the server when the Rotate operation successfully completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_generation: Option<i32>,

    /// The Rotate Interval attribute specifies the interval between rotations of a
    /// Managed Cryptographic Object, measured in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_interval: Option<i32>,

    /// The Rotate Latest attribute is a Boolean that indicates whether the latest
    /// rotation time should be recalculated based on the Rotation Interval and
    /// the Initial Date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_latest: Option<bool>,

    /// The Rotate Name attribute specifies the name of the rotation. This attribute
    /// SHALL be used to specify the algorithm and/or template to be used for the
    /// rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_name: Option<String>,

    /// The Rotate Offset attribute specifies the time offset between the Creation
    /// Date and the Rotation Date of a Managed Cryptographic Object, measured in
    /// seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_offset: Option<i32>,

    /// If True then the server SHALL prevent the object value being retrieved (via the Get operation) unless it is
    // wrapped by another key. The server SHALL set the value to False if the value is not provided by the
    // client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,

    /// The Short Unique Identifier attribute is used for compact identification of objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_unique_identifier: Option<String>,

    /// The State attribute indicates the current state of a Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    /// The Unique Identifier is generated by the key management system
    /// to uniquely identify a Managed Object. It is only REQUIRED to be unique
    /// within the identifier space managed by a single key management system,
    /// however this identifier SHOULD be globally unique in order to allow
    /// for a key management server export of such objects.
    /// This attribute SHALL be assigned by the key management system at creation
    /// or registration time, and then SHALL NOT be changed or deleted
    /// before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,

    /// The Usage Limits attribute is a mechanism for limiting the usage of a
    /// Managed Cryptographic Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits: Option<UsageLimits>,

    /// A vendor specific Attribute is a structure used for sending and
    /// receiving a Managed Object attribute. The Vendor Identification and
    /// Attribute Name are text-strings that are used to identify the attribute.
    /// The Attribute Value is either a primitive data type or structured
    /// object, depending on the attribute. Vendor identification values "x"
    /// and "y" are reserved for KMIP v2.0 and later implementations referencing
    /// KMIP v1.x Custom Attributes.
    /// Vendor Attributes created by the client with Vendor Identification "x"
    /// are not created (provided during object creation), set, added,
    /// adjusted, modified or deleted by the server. Vendor Attributes
    /// created by the server with Vendor Identification "y" are not created
    /// (provided during object creation), set, added, adjusted, modified or
    /// deleted by the client.
    #[allow(clippy::struct_field_names)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_attributes: Option<Vec<VendorAttribute>>,

    /// The X.509 Certificate Identifier attribute is the X.509 certificate identifier
    /// stored in the Issuer and Serial Number attributes from the X.509 Certificate
    /// Issuer and the X.509 Certificate Serial Number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_identifier: Option<X509CertificateIdentifier>,

    /// The X.509 Certificate Issuer attribute is the Distinguished Name of the
    /// Certificate Authority that issued the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_issuer: Option<String>,

    /// The X.509 Certificate Subject attribute is the Distinguished Name of the
    /// entity associated with the public key contained in the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_subject: Option<String>,
}

impl Attributes {
    /// Add a vendor attribute to the list of vendor attributes.
    pub fn add_vendor_attribute(&mut self, vendor_attribute: VendorAttribute) -> &mut Self {
        if let Some(vas) = &mut self.vendor_attributes {
            vas.push(vendor_attribute);
        } else {
            self.vendor_attributes = Some(vec![vendor_attribute]);
        }
        self
    }

    /// Set a vendor attribute to the list of vendor attributes replacing one with an existing value
    /// if any
    pub fn set_vendor_attribute(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
        attribute_value: Vec<u8>,
    ) -> &mut Self {
        let va = self.get_vendor_attribute_mut(vendor_identification, attribute_name);
        va.attribute_value = attribute_value;
        self
    }

    /// Return the vendor attribute with the given vendor identification and
    /// attribute name.
    #[must_use]
    pub fn get_vendor_attribute_value(
        &self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<&[u8]> {
        self.vendor_attributes.as_ref().and_then(|vas| {
            vas.iter()
                .find(|&va| {
                    va.vendor_identification == vendor_identification
                        && va.attribute_name == attribute_name
                })
                .map(|va| va.attribute_value.as_slice())
        })
    }

    /// Return the vendor attribute with the given vendor identification
    /// and remove it from the vendor attributes.
    #[must_use]
    pub fn extract_vendor_attribute_value(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<Vec<u8>> {
        let value = self
            .get_vendor_attribute_value(vendor_identification, attribute_name)
            .map(<[u8]>::to_vec);
        if value.is_some() {
            self.remove_vendor_attribute(vendor_identification, attribute_name);
        }
        value
    }

    /// Return the vendor attribute with the given vendor identification and
    /// attribute name. If the attribute does not exist, an empty
    /// vendor attribute is created and returned.
    #[must_use]
    #[allow(clippy::indexing_slicing)]
    pub fn get_vendor_attribute_mut(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> &mut VendorAttribute {
        let vas = self.vendor_attributes.get_or_insert_with(Vec::new);
        let position = vas.iter().position(|va| {
            va.vendor_identification == vendor_identification && va.attribute_name == attribute_name
        });
        let len = vas.len();
        match position {
            None => {
                vas.push(VendorAttribute {
                    vendor_identification: vendor_identification.to_owned(),
                    attribute_name: attribute_name.to_owned(),
                    attribute_value: vec![],
                });
                &mut vas[len]
            }
            Some(position) => &mut vas[position],
        }
    }

    /// Remove a vendor attribute from the list of vendor attributes.
    pub fn remove_vendor_attribute(&mut self, vendor_identification: &str, attribute_name: &str) {
        if let Some(vas) = self.vendor_attributes.as_mut() {
            vas.retain(|va| {
                va.vendor_identification != vendor_identification
                    || va.attribute_name != attribute_name
            });
            if vas.is_empty() {
                self.vendor_attributes = None;
            }
        }
    }

    /// Get the link to the object.
    #[must_use]
    pub fn get_link(&self, link_type: LinkType) -> Option<LinkedObjectIdentifier> {
        self.link.as_ref().and_then(|links| {
            links
                .iter()
                .find(|&l| l.link_type == link_type)
                .map(|l| l.linked_object_identifier.clone())
        })
    }

    /// Remove the link from the attributes
    pub fn remove_link(&mut self, link_type: LinkType) {
        if let Some(links) = self.link.as_mut() {
            links.retain(|l| l.link_type != link_type);
            if links.is_empty() {
                self.link = None;
            }
        }
    }

    /// Get the parent id of the object.
    #[must_use]
    pub fn get_parent_id(&self) -> Option<LinkedObjectIdentifier> {
        self.get_link(LinkType::ParentLink)
    }

    /// Set a link to an object.
    /// If a link of the same type already exists, it is removed.
    /// There can only be one link of a given type.
    pub fn set_link(
        &mut self,
        link_type: LinkType,
        linked_object_identifier: LinkedObjectIdentifier,
    ) {
        self.remove_link(link_type);
        let links = self.link.get_or_insert_with(Vec::new);
        links.push(Link {
            link_type,
            linked_object_identifier,
        });
    }

    /// Set the attributes's object type.
    pub fn set_object_type(&mut self, object_type: ObjectType) {
        self.object_type = Some(object_type);
    }

    /// Set the attributes's `CryptographicUsageMask`.
    pub fn set_cryptographic_usage_mask(&mut self, mask: Option<CryptographicUsageMask>) {
        self.cryptographic_usage_mask = mask;
    }

    /// Set the bits in `mask` to the attributes's `CryptographicUsageMask` bits.
    pub fn set_cryptographic_usage_mask_bits(&mut self, mask: CryptographicUsageMask) {
        let mask = self
            .cryptographic_usage_mask
            .map_or(mask, |attr_mask| attr_mask | mask);

        self.cryptographic_usage_mask = Some(mask);
    }

    /// Check that `flag` bit is set in object's `CryptographicUsageMask`.
    /// If FIPS mode is disabled, check if Unrestricted bit is set too.
    ///
    /// Return `true` if `flag` has at least one bit set in self's attributes,
    /// return `false` otherwise.
    /// Raise error if object's `CryptographicUsageMask` is None.
    pub fn is_usage_authorized_for(&self, flag: CryptographicUsageMask) -> Result<bool, KmipError> {
        let usage_mask = self.cryptographic_usage_mask.ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                "CryptographicUsageMask is None".to_owned(),
            )
        })?;

        #[cfg(not(feature = "fips"))]
        // In non-FIPS mode, Unrestricted can be allowed.
        let flag = flag | CryptographicUsageMask::Unrestricted;

        Ok((usage_mask & flag).bits() != 0)
    }

    /// Remove the authenticated additional data from the attributes and return it - for AESGCM unwrapping
    #[must_use]
    pub fn remove_aad(&mut self) -> Option<Vec<u8>> {
        let aad = self
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_AAD)
            .map(|value: &[u8]| value.to_vec());

        if aad.is_some() {
            self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_AAD);
        }
        aad
    }

    /// Add the authenticated additional data to the attributes - for AESGCM unwrapping
    pub fn add_aad(&mut self, value: &[u8]) {
        let va = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_AAD.to_owned(),
            attribute_value: value.to_vec(),
        };
        self.add_vendor_attribute(va);
    }
}

impl Attributes {
    /// Merge the attributes from `other` into `self`.
    /// If an attribute is present in both `self` and `other`, and *overwrite* is set,
    /// the value from `other` is used else the value from `self` is used.
    pub fn merge(&mut self, other: &Self, overwrite: bool) {
        // Define a helper macro to merge Option<T> fields
        macro_rules! merge_option_field {
            ($field:ident) => {
                if (overwrite && other.$field.is_some()) || self.$field.is_none() {
                    if other.$field.is_some() {
                        self.$field = other.$field.clone();
                    }
                }
            };
        }

        // Apply the macro to each Option<T> field
        merge_option_field!(activation_date);
        merge_option_field!(alternative_name);
        merge_option_field!(always_sensitive);
        merge_option_field!(application_specific_information);
        merge_option_field!(archive_date);
        merge_option_field!(attribute_index);
        merge_option_field!(certificate_attributes);
        merge_option_field!(certificate_type);
        merge_option_field!(certificate_length);
        merge_option_field!(comment);
        merge_option_field!(compromise_date);
        merge_option_field!(compromise_occurrence_date);
        merge_option_field!(contact_information);
        merge_option_field!(critical);
        merge_option_field!(cryptographic_algorithm);
        merge_option_field!(cryptographic_domain_parameters);
        merge_option_field!(cryptographic_length);
        merge_option_field!(cryptographic_parameters);
        merge_option_field!(cryptographic_usage_mask);
        merge_option_field!(deactivation_date);
        merge_option_field!(description);
        merge_option_field!(destroy_date);
        merge_option_field!(digital_signature_algorithm);
        merge_option_field!(extractable);
        merge_option_field!(fresh);
        merge_option_field!(initial_date);
        merge_option_field!(key_format_type);
        merge_option_field!(key_value_location);
        merge_option_field!(key_value_present);
        merge_option_field!(last_change_date);
        merge_option_field!(lease_time);
        merge_option_field!(nist_key_type);
        merge_option_field!(object_group);
        merge_option_field!(object_group_member);
        merge_option_field!(object_type);
        merge_option_field!(opaque_data_type);
        merge_option_field!(original_creation_date);
        merge_option_field!(pkcs_12_friendly_name);
        merge_option_field!(process_start_date);
        merge_option_field!(protect_stop_date);
        merge_option_field!(protection_level);
        merge_option_field!(protection_period);
        merge_option_field!(protection_storage_masks);
        merge_option_field!(quantum_safe);
        merge_option_field!(random_number_generator);
        merge_option_field!(revocation_reason);
        merge_option_field!(rotate_date);
        merge_option_field!(rotate_generation);
        merge_option_field!(rotate_interval);
        merge_option_field!(rotate_latest);
        merge_option_field!(rotate_name);
        merge_option_field!(rotate_offset);
        merge_option_field!(sensitive);
        merge_option_field!(short_unique_identifier);
        merge_option_field!(state);
        merge_option_field!(unique_identifier);
        merge_option_field!(usage_limits);
        merge_option_field!(x_509_certificate_identifier);
        merge_option_field!(x_509_certificate_issuer);
        merge_option_field!(x_509_certificate_subject);

        // Handle Vec fields specially
        // For name
        if let Some(other_names) = &other.name {
            if self.name.is_none() || overwrite {
                self.name = Some(other_names.clone());
            } else {
                // Merge names without duplicates
                let self_names = self.name.get_or_insert_with(Vec::new);
                for name in other_names {
                    if !self_names.contains(name) {
                        self_names.push(name.clone());
                    }
                }
            }
        }

        // For link
        if let Some(other_links) = &other.link {
            if self.link.is_none() || overwrite {
                self.link = Some(other_links.clone());
            } else {
                // Merge links without duplicates by link_type
                let self_links = self.link.get_or_insert_with(Vec::new);
                for link in other_links {
                    if !self_links.iter().any(|l| l.link_type == link.link_type) {
                        self_links.push(link.clone());
                    }
                }
            }
        }

        // For vendor_attributes
        if let Some(other_vas) = &other.vendor_attributes {
            if self.vendor_attributes.is_none() || overwrite {
                self.vendor_attributes = Some(other_vas.clone());
            } else {
                // Merge vendor attributes without duplicates by vendor_identification and attribute_name
                let self_vas = self.vendor_attributes.get_or_insert_with(Vec::new);
                for va in other_vas {
                    if !self_vas.iter().any(|v| {
                        v.vendor_identification == va.vendor_identification
                            && v.attribute_name == va.attribute_name
                    }) {
                        self_vas.push(va.clone());
                    }
                }
            }
        }
    }
}

/// Structure used in various operations to provide the New Attribute value in the request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Attribute {
    ActivationDate(i64),
    CryptographicAlgorithm(CryptographicAlgorithm),
    CryptographicLength(i32),
    CryptographicParameters(CryptographicParameters),
    CryptographicDomainParameters(CryptographicDomainParameters),
    CryptographicUsageMask(CryptographicUsageMask),
    Links(Vec<Link>),
    VendorAttributes(Vec<VendorAttribute>),
}

impl Display for Attribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActivationDate(activation_date) => {
                write!(f, "ActivationDate: {activation_date}")
            }
            Self::CryptographicAlgorithm(crypto_algorithm) => {
                write!(f, "CryptographicAlgorithm: {crypto_algorithm}")
            }
            Self::CryptographicLength(crypto_length) => {
                write!(f, "CryptographicLength: {crypto_length}")
            }
            Self::CryptographicParameters(crypto_parameters) => {
                write!(f, "CryptographicParameters: {crypto_parameters:?}")
            }
            Self::CryptographicDomainParameters(crypto_domain_parameters) => {
                write!(
                    f,
                    "CryptographicDomainParameters: {crypto_domain_parameters:?}"
                )
            }
            Self::CryptographicUsageMask(crypto_usage_mask) => {
                write!(f, "CryptographicUsageMask: {crypto_usage_mask:?}")
            }
            Self::Links(links) => write!(f, "Links: {links:?}"),
            Self::VendorAttributes(vendor_attributes) => {
                write!(f, "VendorAttributes: {vendor_attributes:?}")
            }
        }
    }
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ActivationDate(activation_date) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("ActivationDate", activation_date)?;
                st.end()
            }
            Self::CryptographicAlgorithm(crypto_algorithm) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicAlgorithm", crypto_algorithm)?;
                st.end()
            }
            Self::CryptographicLength(crypto_length) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicLength", crypto_length)?;
                st.end()
            }
            Self::CryptographicParameters(crypto_parameters) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicParameters", crypto_parameters)?;
                st.end()
            }
            Self::CryptographicDomainParameters(crypto_domain_parameters) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicDomainParameters", crypto_domain_parameters)?;
                st.end()
            }
            Self::CryptographicUsageMask(crypto_usage_mask) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicUsageMask", crypto_usage_mask)?;
                st.end()
            }
            Self::Links(links) => {
                let mut st = serializer.serialize_struct("Attribute", links.len())?;
                for link in links {
                    st.serialize_field("Link", link)?;
                }
                st.end()
            }
            Self::VendorAttributes(vendor_attributes) => {
                let mut st = serializer.serialize_struct("Attribute", vendor_attributes.len())?;
                for vendor_attribute in vendor_attributes {
                    st.serialize_field("VendorAttribute", vendor_attribute)?;
                }
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            ActivationDate,
            CryptographicAlgorithm,
            CryptographicLength,
            CryptographicParameters,
            CryptographicDomainParameters,
            CryptographicUsageMask,
            Link,
            VendorAttribute,
        }

        struct AttributeVisitor;

        impl<'de> Visitor<'de> for AttributeVisitor {
            type Value = Attribute;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct AttributeVisitor")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut activation_date: Option<i64> = None;
                let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
                let mut cryptographic_length: Option<i32> = None;
                let mut cryptographic_parameters: Option<CryptographicParameters> = None;
                let mut cryptographic_domain_parameters: Option<CryptographicDomainParameters> =
                    None;
                let mut cryptographic_usage_mask: Option<CryptographicUsageMask> = None;
                let mut links: Vec<Link> = Vec::new();
                let mut vendor_attributes: Vec<VendorAttribute> = Vec::new();

                while let Some(key) = map.next_key()? {
                    trace!("visit_map: Key: {key:?}");
                    match key {
                        Field::ActivationDate => {
                            if activation_date.is_some() {
                                return Err(de::Error::duplicate_field("activation_date"))
                            }
                            activation_date = Some(map.next_value()?);
                        }
                        Field::CryptographicAlgorithm => {
                            if cryptographic_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_algorithm"))
                            }
                            cryptographic_algorithm = Some(map.next_value()?);
                        }
                        Field::CryptographicLength => {
                            if cryptographic_length.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_length"))
                            }
                            cryptographic_length = Some(map.next_value()?);
                        }
                        Field::CryptographicParameters => {
                            if cryptographic_parameters.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_parameters"))
                            }
                            cryptographic_parameters = Some(map.next_value()?);
                        }
                        Field::CryptographicDomainParameters => {
                            if cryptographic_domain_parameters.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "cryptographic_domain_parameters",
                                ))
                            }
                            cryptographic_domain_parameters = Some(map.next_value()?);
                        }
                        Field::CryptographicUsageMask => {
                            if cryptographic_usage_mask.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_usage_mask"))
                            }
                            cryptographic_usage_mask = Some(map.next_value()?);
                        }
                        Field::Link => {
                            links.push(map.next_value()?);
                        }
                        Field::VendorAttribute => {
                            vendor_attributes.push(map.next_value()?);
                        }
                    }
                }

                trace!("Attribute::deserialize: Link: {:?}", links);
                if let Some(activation_date) = activation_date {
                    return Ok(Attribute::ActivationDate(activation_date))
                } else if let Some(cryptographic_algorithm) = cryptographic_algorithm {
                    return Ok(Attribute::CryptographicAlgorithm(cryptographic_algorithm))
                } else if let Some(cryptographic_length) = cryptographic_length {
                    return Ok(Attribute::CryptographicLength(cryptographic_length))
                } else if let Some(cryptographic_parameters) = cryptographic_parameters {
                    return Ok(Attribute::CryptographicParameters(cryptographic_parameters))
                } else if let Some(cryptographic_domain_parameters) =
                    cryptographic_domain_parameters
                {
                    return Ok(Attribute::CryptographicDomainParameters(
                        cryptographic_domain_parameters,
                    ))
                } else if let Some(cryptographic_usage_mask) = cryptographic_usage_mask {
                    return Ok(Attribute::CryptographicUsageMask(cryptographic_usage_mask))
                } else if !links.is_empty() {
                    return Ok(Attribute::Links(links))
                } else if !vendor_attributes.is_empty() {
                    return Ok(Attribute::VendorAttributes(vendor_attributes))
                }

                Ok(Attribute::ActivationDate(0))
            }
        }

        const FIELDS: &[&str] = &[
            "activation_date",
            "cryptographic_algorithm",
            "cryptographic_length",
            "cryptographic_parameters",
            "cryptographic_domain_parameters",
            "cryptographic_usage_mask",
            "link",
            "public_key_link",
            "vendor_attributes",
        ];
        deserializer.deserialize_struct("Attribute", FIELDS, AttributeVisitor)
    }
}
