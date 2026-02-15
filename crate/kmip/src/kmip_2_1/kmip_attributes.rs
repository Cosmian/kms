use std::fmt::{self, Display, Formatter};

use cosmian_logger::trace;
use serde::{Deserialize, Serialize};
use strum::Display;
use time::OffsetDateTime;

use super::kmip_types::{Digest, UsageLimits, VendorAttributeValue};
use crate::{
    KmipError,
    kmip_0::kmip_types::{
        AlternativeName, ApplicationSpecificInformation, CertificateType, CryptographicUsageMask,
        ErrorReason, KeyValueLocationType, RevocationReason, State, X509CertificateIdentifier,
    },
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_objects::ObjectType,
        kmip_types::{
            CertificateAttributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicParameters, DigitalSignatureAlgorithm, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, Name, NistKeyType, ObjectGroupMember, OpaqueDataType,
            ProtectionLevel, ProtectionStorageMasks, RandomNumberGenerator, UniqueIdentifier,
            VENDOR_ATTR_AAD, VendorAttribute,
        },
    },
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Attributes {
    /// The Activation Date attribute contains the date and time when the
    /// Managed Object MAY begin to be used. This time corresponds to state
    /// transition. The object SHALL NOT be used for any cryptographic
    /// purpose before the Activation Date has been reached. Once the state
    /// transition from Pre-Active has occurred, then this attribute SHALL
    /// NOT be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_date: Option<OffsetDateTime>, // epoch millis

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
    pub archive_date: Option<OffsetDateTime>,

    /// The Attribute Index attribute is used to identify distinct instances of multi-instance attributes.
    /// The combination of the attribute name and the Attribute Index SHALL be unique
    /// within an instance of a managed object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_index: Option<i32>,

    /// The Certificate Attributes are the various items included in a certificate.
    /// The following list is based on RFC2253.
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
    pub compromise_date: Option<OffsetDateTime>,

    /// The Compromise Occurrence Date attribute contains the date and time when the
    /// Managed Object was first believed to be compromised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_occurrence_date: Option<OffsetDateTime>,

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
    pub deactivation_date: Option<OffsetDateTime>,

    /// The Description attribute is a string containing a description of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The Destroy Date attribute contains the date and time when the Managed Object
    /// was destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_date: Option<OffsetDateTime>,

    /// The Digest attribute is a structure that contains the digest value of the key
    /// or secret data (i.e., digest of the Key Material),
    /// certificate (i.e., digest of the Certificate Value),
    /// or opaque object (i.e., digest of the Opaque Data Value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,

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
    pub initial_date: Option<OffsetDateTime>,

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
    pub last_change_date: Option<OffsetDateTime>,

    /// The Lease Time attribute is the length of time in seconds that the object MAY
    /// be retained by the client. KMIP Interval type (32-bit signed integer in TTLV).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<i32>,

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
    pub original_creation_date: Option<OffsetDateTime>,

    /// The PKCS#12 Friendly Name attribute is a string used to identify the key
    /// material stored within a PKCS#12 object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs_12_friendly_name: Option<String>,

    /// The Process Start Date attribute is the date and time that a managed object
    /// is considered to enter the processing state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_start_date: Option<OffsetDateTime>,

    /// The Protect Stop Date attribute is the date and time that a managed object
    /// is considered to enter the protected state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_stop_date: Option<OffsetDateTime>,

    /// The Protection Level attribute indicates the level of protection required for a object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<ProtectionLevel>,

    /// The Protection Period attribute is the length of time in seconds that the
    /// object MAY be protected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_period: Option<i64>,

    /// The Protection Storage Masks attribute contains a list of masks that define
    /// storage protections required for an object.
    /// Accept both singular and plural XML tag forms.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "ProtectionStorageMask")]
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
    pub rotate_date: Option<OffsetDateTime>,

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

    /// If True then the server SHALL prevent the object value being retrieved
    /// (via the Get operation) unless it is wrapped by another key. The server
    /// SHALL set the value to False if the value is not provided by the client.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "Attribute")]
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
    ///
    /// This function will remove the vendor attribute if it exists and add the new vendor attribute.
    ///
    /// # Arguments
    ///     * `vendor_identification` - The vendor identification string.
    ///     * `attribute_name` - The name of the attribute.
    ///     * `attribute_value` - The value of the attribute.
    ///
    /// # Returns
    ///     * `Option<VendorAttributeValue>` - The old value of the attribute if it existed.
    pub fn set_vendor_attribute(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
        attribute_value: VendorAttributeValue,
    ) -> Option<VendorAttributeValue> {
        // Remove the vendor attribute if it exists
        let old = self.remove_vendor_attribute(vendor_identification, attribute_name);
        // Add the new vendor attribute
        self.add_vendor_attribute(VendorAttribute {
            vendor_identification: vendor_identification.to_owned(),
            attribute_name: attribute_name.to_owned(),
            attribute_value,
        });
        old
    }

    /// Return the vendor attribute with the given vendor identification and
    /// attribute name.
    #[must_use]
    pub fn get_vendor_attribute_value(
        &self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<&VendorAttributeValue> {
        let vas = self.vendor_attributes.as_ref()?;
        vas.iter()
            .find(|&va| {
                va.vendor_identification == vendor_identification
                    && va.attribute_name == attribute_name
            })
            .map(|va| &va.attribute_value)
    }

    /// Remove the vendor attribute with the given vendor identification and attribute name.
    /// Returns the value of the removed attribute if it existed.
    pub fn remove_vendor_attribute(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<VendorAttributeValue> {
        if let Some(vas) = &mut self.vendor_attributes {
            // Find the index of the vendor attribute
            let index = vas.iter().position(|va| {
                va.vendor_identification == vendor_identification
                    && va.attribute_name == attribute_name
            });

            // Remove the vendor attribute if found
            if let Some(idx) = index {
                let va = vas.remove(idx);
                // If there are no more vendor attributes, set to None
                if vas.is_empty() {
                    self.vendor_attributes = None;
                }
                return Some(va.attribute_value);
            }
        }
        None
    }

    /// Get the link to the object.
    #[must_use]
    pub fn get_link(&self, link_type: LinkType) -> Option<LinkedObjectIdentifier> {
        let links = self.link.as_ref()?;
        links
            .iter()
            .find(|&l| l.link_type == link_type)
            .map(|l| l.linked_object_identifier.clone())
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
    pub const fn set_object_type(&mut self, object_type: ObjectType) {
        self.object_type = Some(object_type);
    }

    /// Set the attributes's `CryptographicUsageMask`.
    pub const fn set_cryptographic_usage_mask(&mut self, mask: Option<CryptographicUsageMask>) {
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
    /// If FIPS mode is disabled, check if the Unrestricted bit is set too.
    ///
    /// Return `true` if `flag` has at least one bit set in self's attributes,
    /// return `false` otherwise.
    /// Raise error if object's `CryptographicUsageMask` is None.
    pub fn is_usage_authorized_for(&self, flag: CryptographicUsageMask) -> Result<bool, KmipError> {
        trace!(
            "Checking usage mask authorization {:?} for flag: {:?}",
            self.cryptographic_usage_mask, flag
        );
        let usage_mask = self.cryptographic_usage_mask.ok_or_else(|| {
            KmipError::InvalidKmip21Value(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                "CryptographicUsageMask is None".to_owned(),
            )
        })?;

        // In non-FIPS mode, Unrestricted can be allowed.
        #[cfg(feature = "non-fips")]
        let flag = flag | CryptographicUsageMask::Unrestricted;

        Ok((usage_mask & flag).bits() != 0)
    }

    /// Remove the authenticated additional data from the attributes and return it - for AESGCM unwrapping
    #[must_use]
    pub fn remove_aad(&mut self) -> Option<Vec<u8>> {
        let val = self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_AAD)?;
        if let VendorAttributeValue::ByteString(value) = val {
            Some(value)
        } else {
            None
        }
    }

    /// Add the authenticated additional data to the attributes - for AESGCM unwrapping
    pub fn add_aad(&mut self, value: &[u8]) {
        let va = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_AAD.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(value.to_vec()),
        };
        self.add_vendor_attribute(va);
    }

    /// Get the cryptographic length as `usize`.
    ///
    /// Returns `None` if cryptographic length is not set.
    /// Returns `Some(0)` should the cryptographic length be negative.
    pub fn get_cryptographic_length(&mut self) -> Option<usize> {
        self.cryptographic_length
            .map(|cryptographic_length| usize::try_from(cryptographic_length).unwrap_or(0))
    }

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
        merge_option_field!(digest);
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

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Attributes {{")?;
        if let Some(value) = &self.activation_date {
            writeln!(f, "  Activation Date: {value}")?;
        }
        if let Some(value) = &self.alternative_name {
            writeln!(f, "  Alternative Name: {value}")?;
        }
        if let Some(value) = &self.always_sensitive {
            writeln!(f, "  Always Sensitive: {value}")?;
        }
        if let Some(value) = &self.application_specific_information {
            writeln!(f, "  Application Specific Information: {value}")?;
        }
        if let Some(value) = &self.archive_date {
            writeln!(f, "  Archive Date: {value}")?;
        }
        if let Some(value) = &self.attribute_index {
            writeln!(f, "  Attribute Index: {value}")?;
        }
        if let Some(value) = &self.certificate_attributes {
            writeln!(f, "  Certificate Attributes: {value}")?;
        }
        if let Some(value) = &self.certificate_type {
            writeln!(f, "  Certificate Type: {value}")?;
        }
        if let Some(value) = &self.certificate_length {
            writeln!(f, "  Certificate Length: {value}")?;
        }
        if let Some(value) = &self.comment {
            writeln!(f, "  Comment: {value}")?;
        }
        if let Some(value) = &self.compromise_date {
            writeln!(f, "  Compromise Date: {value}")?;
        }
        if let Some(value) = &self.compromise_occurrence_date {
            writeln!(f, "  Compromise Occurrence Date: {value}")?;
        }
        if let Some(value) = &self.contact_information {
            writeln!(f, "  Contact Information: {value}")?;
        }
        if let Some(value) = &self.critical {
            writeln!(f, "  Critical: {value}")?;
        }
        if let Some(value) = &self.cryptographic_algorithm {
            writeln!(f, "  Cryptographic Algorithm: {value}")?;
        }
        if let Some(value) = &self.cryptographic_domain_parameters {
            writeln!(f, "  Cryptographic Domain Parameters: {value}")?;
        }
        if let Some(value) = &self.cryptographic_length {
            writeln!(f, "  Cryptographic Length: {value}")?;
        }
        if let Some(value) = &self.cryptographic_parameters {
            writeln!(f, "  Cryptographic Parameters: {value}")?;
        }
        if let Some(value) = &self.cryptographic_usage_mask {
            writeln!(f, "  Cryptographic Usage Mask: {value}")?;
        }
        if let Some(value) = &self.deactivation_date {
            writeln!(f, "  Deactivation Date: {value}")?;
        }
        if let Some(value) = &self.description {
            writeln!(f, "  Description: {value}")?;
        }
        if let Some(value) = &self.destroy_date {
            writeln!(f, "  Destroy Date: {value}")?;
        }
        if let Some(value) = &self.digest {
            writeln!(f, "  Digest: {value}")?;
        }
        if let Some(value) = &self.digital_signature_algorithm {
            writeln!(f, "  Digital Signature Algorithm: {value}")?;
        }
        if let Some(value) = &self.extractable {
            writeln!(f, "  Extractable: {value}")?;
        }
        if let Some(value) = &self.never_extractable {
            writeln!(f, "  Never Extractable: {value}")?;
        }
        if let Some(value) = &self.fresh {
            writeln!(f, "  Fresh: {value}")?;
        }
        if let Some(value) = &self.initial_date {
            writeln!(f, "  Initial Date: {value}")?;
        }
        if let Some(value) = &self.key_format_type {
            writeln!(f, "  Key Format Type: {value}")?;
        }
        if let Some(value) = &self.key_value_location {
            writeln!(f, "  Key Value Location: {value}")?;
        }
        if let Some(value) = &self.key_value_present {
            writeln!(f, "  Key Value Present: {value}")?;
        }
        if let Some(names) = &self.name {
            for name in names {
                writeln!(f, "  Name: {} ({})", name.name_value, name.name_type)?;
            }
        }
        if let Some(value) = &self.last_change_date {
            writeln!(f, "  Last Change Date: {value}")?;
        }
        if let Some(value) = &self.lease_time {
            writeln!(f, "  Lease Time: {value}")?;
        }
        if let Some(value) = &self.nist_key_type {
            writeln!(f, "  NIST Key Type: {value}")?;
        }
        if let Some(value) = &self.object_group {
            writeln!(f, "  Object Group: {value}")?;
        }
        if let Some(value) = &self.object_group_member {
            writeln!(f, "  Object Group Member: {value}")?;
        }
        if let Some(value) = &self.object_type {
            writeln!(f, "  Object Type: {value}")?;
        }
        if let Some(value) = &self.opaque_data_type {
            writeln!(f, "  Opaque Data Type: {value}")?;
        }
        if let Some(value) = &self.original_creation_date {
            writeln!(f, "  Original Creation Date: {value}")?;
        }
        if let Some(value) = &self.pkcs_12_friendly_name {
            writeln!(f, "  PKCS#12 Friendly Name: {value}")?;
        }
        if let Some(value) = &self.process_start_date {
            writeln!(f, "  Process Start Date: {value}")?;
        }
        if let Some(value) = &self.protect_stop_date {
            writeln!(f, "  Protect Stop Date: {value}")?;
        }
        if let Some(value) = &self.protection_level {
            writeln!(f, "  Protection Level: {value}")?;
        }
        if let Some(value) = &self.protection_period {
            writeln!(f, "  Protection Period: {value}")?;
        }
        if let Some(value) = &self.protection_storage_masks {
            writeln!(f, "  Protection Storage Masks: {value}")?;
        }
        if let Some(value) = &self.quantum_safe {
            writeln!(f, "  Quantum Safe: {value}")?;
        }
        if let Some(value) = &self.random_number_generator {
            writeln!(f, "  Random Number Generator: {value}")?;
        }
        if let Some(value) = &self.revocation_reason {
            writeln!(f, "  Revocation Reason: {value}")?;
        }
        if let Some(value) = &self.rotate_date {
            writeln!(f, "  Rotate Date: {value}")?;
        }
        if let Some(value) = &self.rotate_generation {
            writeln!(f, "  Rotate Generation: {value}")?;
        }
        if let Some(value) = &self.rotate_interval {
            writeln!(f, "  Rotate Interval: {value}")?;
        }
        if let Some(value) = &self.rotate_latest {
            writeln!(f, "  Rotate Latest: {value}")?;
        }
        if let Some(value) = &self.rotate_name {
            writeln!(f, "  Rotate Name: {value}")?;
        }
        if let Some(value) = &self.rotate_offset {
            writeln!(f, "  Rotate Offset: {value}")?;
        }
        if let Some(value) = &self.sensitive {
            writeln!(f, "  Sensitive: {value}")?;
        }
        if let Some(value) = &self.short_unique_identifier {
            writeln!(f, "  Short Unique Identifier: {value}")?;
        }
        if let Some(value) = &self.state {
            writeln!(f, "  State: {value}")?;
        }
        if let Some(value) = &self.unique_identifier {
            writeln!(f, "  Unique Identifier: {value}")?;
        }
        if let Some(value) = &self.usage_limits {
            writeln!(f, "  Usage Limits: {value}")?;
        }
        if let Some(value) = &self.x_509_certificate_identifier {
            writeln!(f, "  X.509 Certificate Identifier: {value}")?;
        }
        if let Some(value) = &self.x_509_certificate_issuer {
            writeln!(f, "  X.509 Certificate Issuer: {value}")?;
        }
        if let Some(value) = &self.x_509_certificate_subject {
            writeln!(f, "  X.509 Certificate Subject: {value}")?;
        }
        if let Some(links) = &self.link {
            for link in links {
                writeln!(f, "  Link: {link}")?;
            }
        }
        if let Some(vendor_attributes) = &self.vendor_attributes {
            for va in vendor_attributes {
                writeln!(f, "  Vendor Attribute: {va}")?;
            }
        }
        writeln!(f, "}}")
    }
}

/// Structure used in various operations to provide the New Attribute value in the request.
/// Each variant corresponds to a field in the Attributes struct.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, strum::VariantNames, Display, Debug)]
#[expect(clippy::large_enum_variant)]
pub enum Attribute {
    /// The Activation Date attribute contains the date and time when the
    /// Managed Object MAY begin to be used. This time corresponds to state
    /// transition. The object SHALL NOT be used for any cryptographic
    /// purpose before the Activation Date has been reached. Once the state
    /// transition from Pre-Active has occurred, then this attribute SHALL
    /// NOT be changed or deleted before the object is destroyed.
    ActivationDate(OffsetDateTime),

    /// The Alternative Name attribute is a variable length text string that is associated
    /// with the unique identifier of the object. It may be used as an alternative name to
    /// identify the object, instead of using its unique identifier.
    AlternativeName(AlternativeName),

    /// The Always Sensitive attribute is a Boolean that indicates whether the key material
    /// of a Symmetric Key, Private Key, or Secret Data object has always been considered
    /// sensitive. This attribute SHOULD only be used for Managed Objects with the Sensitive
    /// attribute set to True.
    AlwaysSensitive(bool),

    /// The Application Specific Information attribute is a structure used to store data specific
    /// to the application(s) using the Managed Object. It consists of the following fields:
    /// - Application Namespace - Text String
    /// - Application Data - Text String
    ApplicationSpecificInformation(ApplicationSpecificInformation),

    /// The Archive Date attribute contains the date and time when the Managed Object was
    /// transferred to the Archive state in the Object States table.
    ArchiveDate(OffsetDateTime),

    /// The Attribute Index attribute is used to identify distinct instances of multi-instance attributes.
    /// The combination of the attribute name and the Attribute Index SHALL be unique
    /// within an instance of a managed object.
    AttributeIndex(i32),

    /// The Certificate Attributes are the various items included in a certificate.
    /// The following list is based on RFC2253.
    CertificateAttributes(CertificateAttributes),

    /// The Certificate Type attribute is a type of certificate (e.g., X.509).
    /// The Certificate Type value SHALL be set by the server when the certificate
    /// is created or registered and then SHALL NOT be changed or deleted
    /// before the object is destroyed.
    CertificateType(CertificateType),

    /// The Certificate Length attribute is the length in bytes of the Certificate object.
    /// The Certificate Length SHALL be set by the server when the object is created or registered,
    /// and then SHALL NOT be changed or deleted before the object is destroyed.
    CertificateLength(i32),

    /// The Comment attribute is a text string that MAY be used to provide additional
    /// information about the object.
    Comment(String),

    /// The Compromise Date attribute contains the date and time when the Managed Object
    /// entered the Compromised state in the Object States table.
    CompromiseDate(OffsetDateTime),

    /// The Compromise Occurrence Date attribute contains the date and time when the
    /// Managed Object was first believed to be compromised.
    CompromiseOccurrenceDate(OffsetDateTime),

    /// The Contact Information attribute is a text string that MAY be used to identify
    /// or provide information about the Contact for the Managed Object.
    ContactInformation(String),

    /// The Critical attribute is a Boolean value that indicates whether the Cryptographic
    /// Usage Mask attribute should be always provided for the object.
    Critical(bool),

    /// The Cryptographic Algorithm of an object. The Cryptographic Algorithm of
    /// a Certificate object identifies the algorithm for the public key
    /// contained within the Certificate. The digital signature algorithm used
    /// to sign the Certificate is identified in the Digital Signature
    /// Algorithm attribute. This attribute SHALL be set by the server when
    /// the object is created or registered and then SHALL NOT be changed or
    /// deleted before the object is destroyed.
    CryptographicAlgorithm(CryptographicAlgorithm),

    /// The Cryptographic Domain Parameters attribute is a structure that
    /// contains fields that MAY need to be specified in the Create Key Pair
    /// Request Payload. Specific fields MAY only pertain to certain types
    /// of Managed Cryptographic Objects.
    CryptographicDomainParameters(CryptographicDomainParameters),

    /// For keys, Cryptographic Length is the length in bits of the clear-text
    /// cryptographic key material of the Managed Cryptographic Object. For
    /// certificates, Cryptographic Length is the length in bits of the public
    /// key contained within the Certificate. This attribute SHALL be set by the
    /// server when the object is created or registered, and then SHALL NOT
    /// be changed or deleted before the object is destroyed.
    CryptographicLength(i32),

    /// Contains cryptographic parameters for operations
    CryptographicParameters(CryptographicParameters),

    /// The Cryptographic Usage Mask attribute defines the cryptographic usage
    /// of a key. This is a bit mask that indicates to the client which
    /// cryptographic functions MAY be performed using the key, and which ones
    /// SHALL NOT be performed.
    CryptographicUsageMask(CryptographicUsageMask),

    /// The Deactivation Date attribute contains the date and time when the
    /// Managed Object SHALL NOT be used for any purpose, except for deletion,
    /// destruction, or re-activation.
    DeactivationDate(OffsetDateTime),

    /// The Description attribute is a string containing a description of the object.
    Description(String),

    /// The Destroy Date attribute contains the date and time when the Managed Object
    /// was destroyed.
    DestroyDate(OffsetDateTime),

    /// The Digest attribute is a structure that contains the digest value of the key
    /// or secret data (i.e., digest of the Key Material),
    /// certificate (i.e., digest of the Certificate Value),
    /// or opaque object (i.e., digest of the Opaque Data Value)
    Digest(Digest),

    /// The Digital Signature Algorithm attribute specifies the digital signature algorithm
    /// that is used with the signing key.
    DigitalSignatureAlgorithm(DigitalSignatureAlgorithm),

    /// The Extractable attribute is a Boolean that indicates whether the Managed Object
    /// may be extracted from the cryptographic device on which it is stored.
    Extractable(bool),

    /// The Fresh attribute indicates if the key value has remained unchanged
    /// since its initial generation.
    Fresh(bool),

    /// The Initial Date attribute contains the date and time when the Managed Object
    /// was first created or registered at the server.
    InitialDate(OffsetDateTime),

    /// The Key Format Type attribute is a required attribute of a
    /// Cryptographic Object. It is set by the server, but a particular Key
    /// Format Type MAY be requested by the client.
    KeyFormatType(KeyFormatType),

    /// The Key Value Location attribute identifies whether the key value is stored
    /// on the KMIP server or stored on an external repository.
    KeyValueLocation(KeyValueLocationType),

    /// The Key Value Present attribute is a Boolean that indicates whether a key value
    /// is present in the key block.
    KeyValuePresent(bool),

    /// The Last Change Date attribute contains the date and time of the last change
    /// to the Managed Object.
    LastChangeDate(OffsetDateTime),

    /// The Lease Time attribute is the length of time in seconds that the object MAY
    /// be retained by the client. KMIP Interval type (32-bit signed integer in TTLV).
    LeaseTime(i32),

    /// The Link attribute is a structure used to create a link from one Managed
    /// Cryptographic Object to another, closely related target Managed
    /// Cryptographic Object.
    Link(Link),

    /// The Name attribute is a structure used to identify and locate the object.
    /// The Name attribute MUST contain the Name Value. The Name Value member is
    /// either a Text String or Enumeration.
    Name(Name),

    /// The Never Extractable attribute is a Boolean that indicates whether the key material
    /// of a Symmetric Key, Private Key, or Secret Data object has never been extractable.
    NeverExtractable(bool),

    /// The NIST Key Type attribute is used to identify the key type used with the
    /// NIST SP 800-56 and SP 800-108 operations.
    NistKeyType(NistKeyType),

    /// The Object Group attribute is a Text String that MAY be used to identify a group
    /// of objects.
    ObjectGroup(String),

    /// The Object Group Member attribute is an enumeration that indicates how the
    /// object is a member of an object group.
    ObjectGroupMember(ObjectGroupMember),

    /// The Object Type of a Managed Object (e.g., public key, private key,
    /// symmetric key, etc.) SHALL be set by the server when the object is
    /// created or registered and then SHALL NOT be changed or deleted before
    /// the object is destroyed.
    ObjectType(ObjectType),

    /// The Opaque Data Type attribute is an enumeration that indicates the type of opaque
    /// data contained in the value of the opaque data attribute.
    OpaqueDataType(OpaqueDataType),

    /// The Original Creation Date attribute contains the date and time the object
    /// was created by the client that first created it.
    OriginalCreationDate(OffsetDateTime),

    /// The PKCS#12 Friendly Name attribute is a string used to identify the key
    /// material stored within a PKCS#12 object.
    Pkcs12FriendlyName(String),

    /// The Process Start Date attribute is the date and time that a managed object
    /// is considered to enter the processing state.
    ProcessStartDate(OffsetDateTime),

    /// The Protect Stop Date attribute is the date and time that a managed object
    /// is considered to enter the protected state.
    ProtectStopDate(OffsetDateTime),

    /// The Protection Level attribute indicates the level of protection required for a object.
    ProtectionLevel(ProtectionLevel),

    /// The Protection Period attribute is the length of time in seconds that the
    /// object MAY be protected.
    ProtectionPeriod(i64),

    /// The Protection Storage Masks attribute contains a list of masks that define
    /// storage protections required for an object.
    ProtectionStorageMasks(ProtectionStorageMasks),

    /// The Quantum Safe attribute is a Boolean that indicates whether the key is
    /// quantum safe or not.
    QuantumSafe(bool),

    /// The Random Number Generator attribute is a structure that contains the details
    /// of the random number generation.
    RandomNumberGenerator(RandomNumberGenerator),

    /// The Revocation Reason attribute is a structure used to indicate why the
    /// Managed Object was revoked.
    RevocationReason(RevocationReason),

    /// The Rotate Date attribute specifies the date and time for the last rotation
    /// of a Managed Cryptographic Object. The Rotate Date attribute SHALL be set by
    /// the server when the Rotate operation successfully completes.
    RotateDate(OffsetDateTime),

    /// The Rotate Generation attribute specifies the generation of the last rotation
    /// of a Managed Cryptographic Object. The Rotate Generation attribute SHALL be set
    /// by the server when the Rotate operation successfully completes.
    RotateGeneration(i32),

    /// The Rotate Interval attribute specifies the interval between rotations of a
    /// Managed Cryptographic Object, measured in seconds.
    RotateInterval(i32),

    /// The Rotate Latest attribute is a Boolean that indicates whether the latest
    /// rotation time should be recalculated based on the Rotation Interval and
    /// the Initial Date.
    RotateLatest(bool),

    /// The Rotate Name attribute specifies the name of the rotation. This attribute
    /// SHALL be used to specify the algorithm and/or template to be used for the
    /// rotation.
    RotateName(String),

    /// The Rotate Offset attribute specifies the time offset between the Creation
    /// Date and the Rotation Date of a Managed Cryptographic Object, measured in
    /// seconds.
    RotateOffset(i32),

    /// If True then the server SHALL prevent the object value being retrieved (via the Get operation) unless it is
    /// wrapped by another key. The server SHALL set the value to False if the value is not provided by the
    /// client.
    Sensitive(bool),

    /// The Short Unique Identifier attribute is used for compact identification of objects.
    ShortUniqueIdentifier(String),

    /// The State attribute indicates the current state of a Managed Object.
    State(State),

    /// The Unique Identifier is generated by the key management system
    /// to uniquely identify a Managed Object. It is only REQUIRED to be unique
    /// within the identifier space managed by a single key management system,
    /// however this identifier SHOULD be globally unique.
    UniqueIdentifier(UniqueIdentifier),

    /// The Usage Limits attribute is a mechanism for limiting the usage of a
    /// Managed Cryptographic Object.
    UsageLimits(UsageLimits),

    /// A vendor specific Attribute is a structure used for sending and
    /// receiving a Managed Object attribute. The Vendor Identification and
    /// Attribute Name are text-strings that are used to identify the attribute.
    #[serde(rename = "Attribute")]
    VendorAttribute(VendorAttribute),

    /// The X.509 Certificate Identifier attribute is the X.509 certificate identifier
    /// stored in the Issuer and Serial Number attributes from the X.509 Certificate
    /// Issuer and the X.509 Certificate Serial Number.
    X509CertificateIdentifier(X509CertificateIdentifier),

    /// The X.509 Certificate Issuer attribute is the Distinguished Name of the
    /// Certificate Authority that issued the certificate.
    X509CertificateIssuer(String),

    /// The X.509 Certificate Subject attribute is the Distinguished Name of the
    /// entity associated with the public key contained in the certificate.
    X509CertificateSubject(String),
}

impl From<Attributes> for Vec<Attribute> {
    fn from(attributes: Attributes) -> Self {
        let mut vec = Self::new();
        if let Some(activation_date) = attributes.activation_date {
            vec.push(Attribute::ActivationDate(activation_date));
        }
        if let Some(alternative_name) = attributes.alternative_name {
            vec.push(Attribute::AlternativeName(alternative_name));
        }
        if let Some(always_sensitive) = attributes.always_sensitive {
            vec.push(Attribute::AlwaysSensitive(always_sensitive));
        }
        if let Some(application_specific_information) = attributes.application_specific_information
        {
            vec.push(Attribute::ApplicationSpecificInformation(
                application_specific_information,
            ));
        }
        if let Some(archive_date) = attributes.archive_date {
            vec.push(Attribute::ArchiveDate(archive_date));
        }
        if let Some(attribute_index) = attributes.attribute_index {
            vec.push(Attribute::AttributeIndex(attribute_index));
        }
        if let Some(certificate_attributes) = attributes.certificate_attributes {
            vec.push(Attribute::CertificateAttributes(certificate_attributes));
        }
        if let Some(certificate_type) = attributes.certificate_type {
            vec.push(Attribute::CertificateType(certificate_type));
        }
        if let Some(certificate_length) = attributes.certificate_length {
            vec.push(Attribute::CertificateLength(certificate_length));
        }
        if let Some(comment) = attributes.comment {
            vec.push(Attribute::Comment(comment));
        }
        if let Some(compromise_date) = attributes.compromise_date {
            vec.push(Attribute::CompromiseDate(compromise_date));
        }
        if let Some(compromise_occurrence_date) = attributes.compromise_occurrence_date {
            vec.push(Attribute::CompromiseOccurrenceDate(
                compromise_occurrence_date,
            ));
        }
        if let Some(contact_information) = attributes.contact_information {
            vec.push(Attribute::ContactInformation(contact_information));
        }
        if let Some(critical) = attributes.critical {
            vec.push(Attribute::Critical(critical));
        }
        if let Some(cryptographic_algorithm) = attributes.cryptographic_algorithm {
            vec.push(Attribute::CryptographicAlgorithm(cryptographic_algorithm));
        }
        if let Some(cryptographic_domain_parameters) = attributes.cryptographic_domain_parameters {
            vec.push(Attribute::CryptographicDomainParameters(
                cryptographic_domain_parameters,
            ));
        }
        if let Some(cryptographic_length) = attributes.cryptographic_length {
            vec.push(Attribute::CryptographicLength(cryptographic_length));
        }
        if let Some(cryptographic_parameters) = attributes.cryptographic_parameters {
            vec.push(Attribute::CryptographicParameters(cryptographic_parameters));
        }
        if let Some(cryptographic_usage_mask) = attributes.cryptographic_usage_mask {
            vec.push(Attribute::CryptographicUsageMask(cryptographic_usage_mask));
        }
        if let Some(deactivation_date) = attributes.deactivation_date {
            vec.push(Attribute::DeactivationDate(deactivation_date));
        }
        if let Some(description) = attributes.description {
            vec.push(Attribute::Description(description));
        }
        if let Some(destroy_date) = attributes.destroy_date {
            vec.push(Attribute::DestroyDate(destroy_date));
        }
        if let Some(digest) = attributes.digest {
            vec.push(Attribute::Digest(digest));
        }
        if let Some(digital_signature_algorithm) = attributes.digital_signature_algorithm {
            vec.push(Attribute::DigitalSignatureAlgorithm(
                digital_signature_algorithm,
            ));
        }
        if let Some(extractable) = attributes.extractable {
            vec.push(Attribute::Extractable(extractable));
        }
        if let Some(fresh) = attributes.fresh {
            vec.push(Attribute::Fresh(fresh));
        }
        if let Some(initial_date) = attributes.initial_date {
            vec.push(Attribute::InitialDate(initial_date));
        }
        if let Some(key_format_type) = attributes.key_format_type {
            vec.push(Attribute::KeyFormatType(key_format_type));
        }
        if let Some(key_value_location) = attributes.key_value_location {
            vec.push(Attribute::KeyValueLocation(key_value_location));
        }
        if let Some(key_value_present) = attributes.key_value_present {
            vec.push(Attribute::KeyValuePresent(key_value_present));
        }
        if let Some(last_change_date) = attributes.last_change_date {
            vec.push(Attribute::LastChangeDate(last_change_date));
        }
        if let Some(lease_time) = attributes.lease_time {
            vec.push(Attribute::LeaseTime(lease_time));
        }
        if let Some(links) = attributes.link {
            for link in links {
                vec.push(Attribute::Link(link));
            }
        }
        if let Some(names) = attributes.name {
            for name in names {
                vec.push(Attribute::Name(name));
            }
        }
        if let Some(nist_key_type) = attributes.nist_key_type {
            vec.push(Attribute::NistKeyType(nist_key_type));
        }
        if let Some(object_group) = attributes.object_group {
            vec.push(Attribute::ObjectGroup(object_group));
        }
        if let Some(object_group_member) = attributes.object_group_member {
            vec.push(Attribute::ObjectGroupMember(object_group_member));
        }
        if let Some(object_type) = attributes.object_type {
            vec.push(Attribute::ObjectType(object_type));
        }
        if let Some(opaque_data_type) = attributes.opaque_data_type {
            vec.push(Attribute::OpaqueDataType(opaque_data_type));
        }
        if let Some(original_creation_date) = attributes.original_creation_date {
            vec.push(Attribute::OriginalCreationDate(original_creation_date));
        }
        if let Some(pkcs_12_friendly_name) = attributes.pkcs_12_friendly_name {
            vec.push(Attribute::Pkcs12FriendlyName(pkcs_12_friendly_name));
        }
        if let Some(process_start_date) = attributes.process_start_date {
            vec.push(Attribute::ProcessStartDate(process_start_date));
        }
        if let Some(protect_stop_date) = attributes.protect_stop_date {
            vec.push(Attribute::ProtectStopDate(protect_stop_date));
        }
        if let Some(protection_level) = attributes.protection_level {
            vec.push(Attribute::ProtectionLevel(protection_level));
        }
        if let Some(protection_period) = attributes.protection_period {
            vec.push(Attribute::ProtectionPeriod(protection_period));
        }
        if let Some(protection_storage_masks) = attributes.protection_storage_masks {
            vec.push(Attribute::ProtectionStorageMasks(protection_storage_masks));
        }
        if let Some(quantum_safe) = attributes.quantum_safe {
            vec.push(Attribute::QuantumSafe(quantum_safe));
        }
        if let Some(random_number_generator) = attributes.random_number_generator {
            vec.push(Attribute::RandomNumberGenerator(random_number_generator));
        }
        if let Some(revocation_reason) = attributes.revocation_reason {
            vec.push(Attribute::RevocationReason(revocation_reason));
        }
        if let Some(rotate_date) = attributes.rotate_date {
            vec.push(Attribute::RotateDate(rotate_date));
        }
        if let Some(rotate_generation) = attributes.rotate_generation {
            vec.push(Attribute::RotateGeneration(rotate_generation));
        }
        if let Some(rotate_interval) = attributes.rotate_interval {
            vec.push(Attribute::RotateInterval(rotate_interval));
        }
        if let Some(rotate_latest) = attributes.rotate_latest {
            vec.push(Attribute::RotateLatest(rotate_latest));
        }
        if let Some(rotate_name) = attributes.rotate_name {
            vec.push(Attribute::RotateName(rotate_name));
        }
        if let Some(rotate_offset) = attributes.rotate_offset {
            vec.push(Attribute::RotateOffset(rotate_offset));
        }
        if let Some(sensitive) = attributes.sensitive {
            vec.push(Attribute::Sensitive(sensitive));
        }
        if let Some(short_unique_identifier) = attributes.short_unique_identifier {
            vec.push(Attribute::ShortUniqueIdentifier(short_unique_identifier));
        }
        if let Some(state) = attributes.state {
            vec.push(Attribute::State(state));
        }
        if let Some(unique_identifier) = attributes.unique_identifier {
            vec.push(Attribute::UniqueIdentifier(unique_identifier));
        }
        if let Some(usage_limits) = attributes.usage_limits {
            vec.push(Attribute::UsageLimits(usage_limits));
        }
        if let Some(vendor_attributes) = attributes.vendor_attributes {
            for vendor_attribute in vendor_attributes {
                vec.push(Attribute::VendorAttribute(vendor_attribute));
            }
        }
        if let Some(x_509_certificate_identifier) = attributes.x_509_certificate_identifier {
            vec.push(Attribute::X509CertificateIdentifier(
                x_509_certificate_identifier,
            ));
        }
        if let Some(x_509_certificate_issuer) = attributes.x_509_certificate_issuer {
            vec.push(Attribute::X509CertificateIssuer(x_509_certificate_issuer));
        }
        if let Some(x_509_certificate_subject) = attributes.x_509_certificate_subject {
            vec.push(Attribute::X509CertificateSubject(x_509_certificate_subject));
        }
        vec
    }
}

impl From<Vec<Attribute>> for Attributes {
    fn from(attributes: Vec<Attribute>) -> Self {
        let mut attrs = Self::default();
        for attribute in attributes {
            match attribute {
                Attribute::ActivationDate(value) => attrs.activation_date = Some(value),
                Attribute::AlternativeName(value) => attrs.alternative_name = Some(value),
                Attribute::AlwaysSensitive(value) => attrs.always_sensitive = Some(value),
                Attribute::ApplicationSpecificInformation(value) => {
                    attrs.application_specific_information = Some(value);
                }
                Attribute::ArchiveDate(value) => attrs.archive_date = Some(value),
                Attribute::AttributeIndex(value) => attrs.attribute_index = Some(value),
                Attribute::CertificateAttributes(value) => {
                    attrs.certificate_attributes = Some(value);
                }
                Attribute::CertificateType(value) => attrs.certificate_type = Some(value),
                Attribute::CertificateLength(value) => attrs.certificate_length = Some(value),
                Attribute::Comment(value) => attrs.comment = Some(value),
                Attribute::CompromiseDate(value) => attrs.compromise_date = Some(value),
                Attribute::CompromiseOccurrenceDate(value) => {
                    attrs.compromise_occurrence_date = Some(value);
                }
                Attribute::ContactInformation(value) => attrs.contact_information = Some(value),
                Attribute::Critical(value) => attrs.critical = Some(value),
                Attribute::CryptographicAlgorithm(value) => {
                    attrs.cryptographic_algorithm = Some(value);
                }
                Attribute::CryptographicDomainParameters(value) => {
                    attrs.cryptographic_domain_parameters = Some(value);
                }
                Attribute::CryptographicLength(value) => attrs.cryptographic_length = Some(value),
                Attribute::CryptographicParameters(value) => {
                    attrs.cryptographic_parameters = Some(value);
                }
                Attribute::CryptographicUsageMask(value) => {
                    attrs.cryptographic_usage_mask = Some(value);
                }
                Attribute::DeactivationDate(value) => attrs.deactivation_date = Some(value),
                Attribute::Description(value) => attrs.description = Some(value),
                Attribute::DestroyDate(value) => attrs.destroy_date = Some(value),
                Attribute::Digest(value) => attrs.digest = Some(value),
                Attribute::DigitalSignatureAlgorithm(value) => {
                    attrs.digital_signature_algorithm = Some(value);
                }
                Attribute::Extractable(value) => attrs.extractable = Some(value),
                Attribute::Fresh(value) => attrs.fresh = Some(value),
                Attribute::InitialDate(value) => attrs.initial_date = Some(value),
                Attribute::KeyFormatType(value) => attrs.key_format_type = Some(value),
                Attribute::KeyValueLocation(value) => attrs.key_value_location = Some(value),
                Attribute::KeyValuePresent(value) => attrs.key_value_present = Some(value),
                Attribute::LastChangeDate(value) => attrs.last_change_date = Some(value),
                Attribute::LeaseTime(value) => attrs.lease_time = Some(value),
                Attribute::Link(value) => {
                    attrs.link.get_or_insert_with(Vec::new).push(value);
                }
                Attribute::Name(value) => {
                    attrs.name.get_or_insert_with(Vec::new).push(value);
                }
                Attribute::NistKeyType(value) => attrs.nist_key_type = Some(value),
                Attribute::ObjectGroup(value) => attrs.object_group = Some(value),
                Attribute::ObjectGroupMember(value) => attrs.object_group_member = Some(value),
                Attribute::ObjectType(value) => attrs.object_type = Some(value),
                Attribute::OpaqueDataType(value) => attrs.opaque_data_type = Some(value),
                Attribute::OriginalCreationDate(value) => {
                    attrs.original_creation_date = Some(value);
                }
                Attribute::Pkcs12FriendlyName(value) => attrs.pkcs_12_friendly_name = Some(value),
                Attribute::ProcessStartDate(value) => attrs.process_start_date = Some(value),
                Attribute::ProtectStopDate(value) => attrs.protect_stop_date = Some(value),
                Attribute::ProtectionLevel(value) => attrs.protection_level = Some(value),
                Attribute::ProtectionPeriod(value) => attrs.protection_period = Some(value),
                Attribute::ProtectionStorageMasks(value) => {
                    attrs.protection_storage_masks = Some(value);
                }
                Attribute::QuantumSafe(value) => attrs.quantum_safe = Some(value),
                Attribute::RandomNumberGenerator(value) => {
                    attrs.random_number_generator = Some(value);
                }
                Attribute::RevocationReason(value) => attrs.revocation_reason = Some(value),
                Attribute::RotateDate(value) => attrs.rotate_date = Some(value),
                Attribute::RotateGeneration(value) => attrs.rotate_generation = Some(value),
                Attribute::RotateInterval(value) => attrs.rotate_interval = Some(value),
                Attribute::RotateLatest(value) => attrs.rotate_latest = Some(value),
                Attribute::RotateName(value) => attrs.rotate_name = Some(value),
                Attribute::RotateOffset(value) => attrs.rotate_offset = Some(value),
                Attribute::Sensitive(value) => attrs.sensitive = Some(value),
                Attribute::ShortUniqueIdentifier(value) => {
                    attrs.short_unique_identifier = Some(value);
                }
                Attribute::State(value) => attrs.state = Some(value),
                Attribute::UniqueIdentifier(value) => attrs.unique_identifier = Some(value),
                Attribute::UsageLimits(value) => attrs.usage_limits = Some(value),
                Attribute::VendorAttribute(value) => {
                    attrs
                        .vendor_attributes
                        .get_or_insert_with(Vec::new)
                        .push(value);
                }
                Attribute::X509CertificateIdentifier(value) => {
                    attrs.x_509_certificate_identifier = Some(value);
                }
                Attribute::X509CertificateIssuer(value) => {
                    attrs.x_509_certificate_issuer = Some(value);
                }
                Attribute::X509CertificateSubject(value) => {
                    attrs.x_509_certificate_subject = Some(value);
                }
                // Map NeverExtractable to the Attributes field
                Attribute::NeverExtractable(value) => {
                    attrs.never_extractable = Some(value);
                }
            }
        }
        attrs
    }
}
