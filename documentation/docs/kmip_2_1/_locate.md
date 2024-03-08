#### Specification

This operation requests that the server search for one or more Managed Objects, depending on the attributes specified in
the request. All attributes are allowed to be used. The request MAY contain a Maximum Items field, which specifies the
maximum number of objects to be returned. If the Maximum Items field is omitted, then the server MAY return all objects
matched or MAY impose an internal maximum limit due to resource limitations.

The request MAY contain an Offset Items field, which specifies the number of objects to skip that satisfy the
identification criteria specified in the request. An Offset Items field of 0 is the same as omitting the Offset Items
field. If both Offset Items and Maximum Items are specified in the request, the server skips Offset Items objects and
returns up to Maximum Items objects.

If more than one object satisfies the identification criteria specified in the request, then the response MAY contain
Unique Identifiers for multiple Managed Objects. Responses containing Unique Identifiers for multiple objects SHALL be
returned in descending order of object creation (most recently created object first). Returned objects SHALL match all
of the attributes in the request. If no objects match, then an empty response payload is returned. If no attribute is
specified in the request, any object SHALL be deemed to match the Locate request. The response MAY include Located Items
which is the count of all objects that satisfy the identification criteria.

The server returns a list of Unique Identifiers of the found objects, which then MAY be retrieved using the Get
operation. If the objects are archived, then the Recover and Get operations are REQUIRED to be used to obtain those
objects. If a single Unique Identifier is returned to the client, then the server SHALL copy the Unique Identifier
returned by this operation into the ID Placeholder variable. If the Locate operation matches more than one object, and
the Maximum Items value is omitted in the request, or is set to a value larger than one, then the server SHALL empty the
ID Placeholder, causing any subsequent operations that are batched with the Locate, and which do not specify a Unique
Identifier explicitly, to fail. This ensures that these batched operations SHALL proceed only if a single object is
returned by Locate.

The Date attributes in the Locate request (e.g., Initial Date, Activation Date, etc.) are used to specify a time or a
time range for the search. If a single instance of a given Date attribute is used in the request (e.g., the Activation
Date), then objects with the same Date attribute are considered to be matching candidate objects. If two instances of
the same Date attribute are used (i.e., with two different values specifying a range), then objects for which the Date
attribute is inside or at a limit of the range are considered to be matching candidate objects. If a Date attribute is
set to its largest possible value, then it is equivalent to an undefined attribute.

When the Cryptographic Usage Mask attribute is specified in the request, candidate objects are compared against this
field via an operation that consists of a logical AND of the requested mask with the mask in the candidate object, and
then a comparison of the resulting value with the requested mask. For example, if the request contains a mask value of
10001100010000, and a candidate object mask contains 10000100010000, then the logical AND of the two masks is
10000100010000, which is compared against the mask value in the request (10001100010000) and the match fails. This means
that a matching candidate object has all of the bits set in its mask that are set in the requested mask, but MAY have
additional bits set.

When the Usage Limits attribute is specified in the request, matching candidate objects SHALL have a Usage Limits Count
and Usage Limits Total equal to or larger than the values specified in the request.

When an attribute that is defined as a structure is specified, all of the structure fields are not REQUIRED to be
specified. For instance, for the Link attribute, if the Linked Object Identifier value is specified without the Link
Type value, then matching candidate objects have the Linked Object Identifier as specified, irrespective of their Link
Type.

When the Object Group attribute and the Object Group Member flag are specified in the request, and the value specified
for Object Group Member is `Group Member Fresh`, matching candidate objects SHALL be fresh objects from the object
group. If there are no more fresh objects in the group, the server MAY choose to generate a new object on-the-fly, based
on server policy. If the value specified for Object Group Member is `Group Member Default`, the server locates the
default object as defined by server policy.

The Storage Status Mask field is used to indicate whether on-line objects (not archived or destroyed), archived objects,
destroyed objects or any combination of the above are to be searched.The server SHALL NOT return unique identifiers for
objects that are destroyed unless the Storage Status Mask field includes the Destroyed Storage indicator. The server
SHALL NOT return unique identifiers for objects that are archived unless the Storage Status Mask field includes the
Archived Storage indicator.

#### Implementation

Locate allows finding objects:

- by their tags (see [tagging](./tagging.md))
- by their `Cryptographic Algorithm`. Some supported values are: `AES`, `RSA`, `ECDSA`, `ECDH`, `EC`,
   `ChaCha20`, `Poly1305`,
   `ChaCha20Poly1305`, `Ed25519`, `Ed448`, `CoverCrypt`
- by their `Key Format Type`. Some supported values are: `Raw`, `Opaque`, `PKCS1`, `PKCS8`, `X509`, `ECPrivateKey`,
   `TransparentSymmetricKey`, `TransparentRSAPrivateKey`, `TransparentRSAPublicKey`, `TransparentECPrivateKey`,
   `TransparentECPublicKey`, `PKCS12`, `CoverCryptSecretKey`, `CoverCryptPublicKey`
- by their links to other objects:
  - a public key (`Public Key Link`)
  - a private key (`Private Key Link`)
  - a certificate (`Certificate Link`)
- for certificates:
  - by subject common name
  - by certificate spki

### Example - Symmetric Keys using the `_kk` tag

All symmetric keys are tagged with the system tag `_kk`.
Multiple tags can be used locate objects; a JSON array of tags is used to specify multiple tags which is then
serialized to hex.

=== "Request"

    ```json
        {
          "tag": "Locate",
          "type": "Structure",
          "value": [
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "VendorAttributes",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "VendorAttributes",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "VendorIdentification",
                          "type": "TextString",
                          "value": "cosmian"
                        },
                        {
                          "tag": "AttributeName",
                          "type": "TextString",
                          "value": "tag"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          // hex encoding of ["_kk"]
                          "value": "5B225F6B6B225D"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "LocateResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "LocatedItems",
              "type": "Integer",
              "value": 8
            },
            {
              "tag": "UniqueIdentifier",
              "type": "Structure",
              "value": [
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "1a35b3be-1a1a-4798-a3aa-d9fc67298461"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "5dc81bb2-648f-485f-b804-c6ea45467056"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "6ce69a21-5b4b-470a-84e7-0e1385947527"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "ad9ba3be-93c7-4fac-a271-ef186fd645ce"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "bac520f6-461f-40e5-b8f2-7927d8ae310b"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "da5844b6-4d29-46b8-a657-9dfd449f8560"
                },
                {
                  "tag": "UniqueIdentifier",
                  "type": "TextString",
                  "value": "ebddca55-6027-4c86-ac1f-6b38dcfd6ead"
                }
              ]
            }
          ]
        }
    ```
