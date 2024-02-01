### Specification

This operation requests one or more attributes associated with a Managed Object. The object is specified by its Unique
Identifier, and the attributes are specified by their name in the request. If a specified attribute has multiple
instances, then all instances are returned. If a specified attribute does not exist (i.e., has no value), then it SHALL
NOT be present in the returned response. If none of the requested attributes exist, then the response SHALL consist only
of the Unique Identifier. The same Attribute Reference SHALL NOT be present more than once in a request.

If no Attribute Reference is provided, the server SHALL return all attributes.

### Implementation

This operation can be applied to all [supported objects](./objects.md).

### Example - A symmetric key

Get the attributes of a symmetric key by its unique identifier `027cced1-ff2b-4bd3-a200-db1041583bdc`.

Corresponding `ckms` CLI command:

```bash
  ckms get-attributes -i 027cced1-ff2b-4bd3-a200-db1041583bdc
```

The request has an empty `AttributeReference` structure, which means that all
attributes are requested.

The response contains all the system and user tags associated with the key. This is the hex encoded value of a JSON
array with value

```json
["MySymmetricKey", "_kk"]
```

=== "Request"

    ```json
        {
          "tag": "GetAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
            },
            {
              "tag": "AttributeReference",
              "type": "Structure",
              "value": []
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetAttributesResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
            },
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "AES"
                },
                {
                  "tag": "CryptographicLength",
                  "type": "Integer",
                  "value": 256
                },
                {
                  "tag": "CryptographicUsageMask",
                  "type": "Integer",
                  "value": 2108
                },
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "TransparentSymmetricKey"
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "SplitKey"
                },
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
                          // This is the hex value of a JSON array of system and user tags: ["MySymmetricKey","_kk"]
                          "value": "5B224D7953796D6D65747269634B6579222C225F6B6B225D"
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

### Example - A NIST P-256 private key

Get the attributes of a NIST P-256 private key.

Corresponding `ckms` CLI command:

```bash
  ckms get-attributes -i 927adccb-f59a-4cc9-a9e3-1eeb958c601f
```

The request has an empty `AttributeReference` structure, which means that
all attributes are requested.

In the response, please note:

- the `RecommendedCurve` is `P256`, the KMIP name for NIST P-256
- the `tag` is the hex encoded value of a JSON array with value `["_sk"]`, the system tag for a private key

=== "Request"

    ```json
        {
          "tag": "GetAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "927adccb-f59a-4cc9-a9e3-1eeb958c601f"
            },
            {
              "tag": "AttributeReference",
              "type": "Structure",
              "value": []
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetAttributesResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "927adccb-f59a-4cc9-a9e3-1eeb958c601f"
            },
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CryptographicAlgorithm",
                  "type": "Enumeration",
                  "value": "ECDH"
                },
                {
                  "tag": "CryptographicLength",
                  "type": "Integer",
                  "value": 256
                },
                {
                  "tag": "CryptographicDomainParameters",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "QLength",
                      "type": "Integer",
                      "value": 256
                    },
                    {
                      "tag": "RecommendedCurve",
                      "type": "Enumeration",
                      // the curve
                      "value": "P256"
                    }
                  ]
                },
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "TransparentECPrivateKey"
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "PrivateKey"
                },
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
                          // hex encoded value of a JSON array of system tag: ["_sk"]
                          "value": "5B225F736B225D"
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

### Example - A certificate imported as part of a PKCS#12 container

Get the attributes of the certificate imported as part of a PKCS#12 container (see [Import](./_import.md) for
reference to the imported PKCS#12 container). The certificate is linked to a private key was signed by an
intermediate certificate imported as part of the same container.

Corresponding `ckms` CLI command:

```bash
  ckms get-attributes -i d2f4e937-dda9-4a86-bbe8-c866646a612f
```

The request has an empty `AttributeReference` structure, which means that all attributes are requested.

Please note in the response:

- the `Link` to the private key
- the `Link` to the intermediate certificate
- the presence of all the system and user tags associated with the certificate. This is the hex encoded value of a
  JSON array with value

=== "Request"

    ```json
        {
          "tag": "GetAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "d2f4e937-dda9-4a86-bbe8-c866646a612f"
            },
            {
              "tag": "AttributeReference",
              "type": "Structure",
              "value": []
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetAttributesResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "d2f4e937-dda9-4a86-bbe8-c866646a612f"
            },
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyFormatType",
                  "type": "Enumeration",
                  "value": "X509"
                },
                {
                  "tag": "Link",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "Link",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "LinkType",
                          "type": "Enumeration",
                          "value": "PrivateKeyLink"
                        },
                        {
                          "tag": "LinkedObjectIdentifier",
                          "type": "TextString",
                          // the private key
                          "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
                        }
                      ]
                    },
                    {
                      "tag": "Link",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "LinkType",
                          "type": "Enumeration",
                          "value": "CertificateLink"
                        },
                        {
                          "tag": "LinkedObjectIdentifier",
                          "type": "TextString",
                          // the intermediate certificate, which is the issuer of the certificate
                          "value": "0c9028bc-c518-40d3-8362-12a1edfddab0"
                        }
                      ]
                    }
                  ]
                },
                {
                  "tag": "ObjectType",
                  "type": "Enumeration",
                  "value": "Certificate"
                },
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
                        // This is the hex encoded value of a JSON array of system and user tags
                          "value": "5B225F63657274222C225F636572745F636E3D4D7920736572766572222C225F636572745F73706B693D36353565303430393938383461663363636133653362313164393038626238666432373237306263222C224D79504B43533132222C225F636572745F6973737565723D30633930323862632D633531382D343064332D383336322D313261316564666464616230222C225F636572745F736B3D62663631346434352D356133652D343962392D393563302D353538366433633064313762225D"
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
