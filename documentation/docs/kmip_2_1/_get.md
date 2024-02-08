#### Specification

This operation requests that the server returns the Managed Object specified by its Unique Identifier. Only a single
object is returned.

The response contains the Unique Identifier of the object, along with the object itself, which MAY be wrapped using a
wrapping key as specified in the request. The following key format capabilities SHALL be assumed by the client;
restrictions apply when the client requests the server to return an object in a particular
format:

- If a client registers a key in a given format, the server SHALL be able to return the key during the Get operation in
  the same format that was used when the key was registered.

- Any other format conversion MAY be supported by the server.

If Key Format Type is specified to be PKCS#12 then the response payload shall be a PKCS#12 container as specified
by [RFC7292].

The Unique Identifier shall be either that of a private key or certificate to be included in the response.

The container shall be protected using the Secret Data object specified via the private key or certificate's PKCS#12
Password Link. The current certificate chain shall also be included as determined by using the private key's Public Key
link to get the corresponding public key (where relevant) and then using that public key's PKCS#12 Certificate Link to
get the base certificate, and then using each certificate's Certificate Link to build the certificate chain. It is an
error if there is more than one valid certificate chain.

#### Implementation

The `Get` operation allows exporting `Active` objects only.
When an object is `Destroyed` or `Deactivated`, the `Export` operation must be used instead.

Key wrapping and unwrapping on export is supported for all keys. Please check the [algorithms page](../algorithms.md)
for more details.

For the list of supported key formats, please check the [formats page](./formats.md).

#### Example - A symmetric key

Exporting a symmetric key `027cced1-ff2b-4bd3-a200-db1041583bdc` (go to [Create](./_create.md) to see how to create the
symmetric key).

Instead of using the UID of the key, we can use the unique tag of the key `MySymmetricKey`. The key must be uniquely
identified. It is possible to use multiple tags to identify a key; for instance symmetric keys automatically get a
*system* tag `_kk`. See [tagging](./tagging.md) for more information on tags.

The response is in `Raw`format, the default format for symmetric keys specified by KMIP 2.1; see the [formats page](.
/formats.md) for details.

Corresponding `ckms` CLI command:

```bash
  ckms sym keys export -t "MySymmetricKey" /tmp/sym_key.json
```

=== "Request"

    ```json
        {
          "tag": "Get",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "[\"MySymmetricKey\"]"
            },
            {
              "tag": "KeyWrapType",
              "type": "Enumeration",
              "value": "AsRegistered"
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "SymmetricKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyBlock",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "KeyFormatType",
                      "type": "Enumeration",
                      "value": "Raw"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          "value": "0B3E539510BABD291BB9FEC2A390C833B05465F33374575CE4AAFFABD5E93020"
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
                              "value": "SymmetricKey"
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "tag": "CryptographicAlgorithm",
                      "type": "Enumeration",
                      "value": "AES"
                    },
                    {
                      "tag": "CryptographicLength",
                      "type": "Integer",
                      "value": 256
                    }
                  ]
                }
              ]
            }
          ]
        }
    ```

#### Example - A wrapped Covercrypt user key

Exporting a wrapped Covercrypt user key `df871e79-0923-47cd-9078-bbec83287c85` (go to [Create](./_create.md) to
see how to create the Covercrypt user key) after wrapping it with symmetric key
`027cced1-ff2b-4bd3-a200-db1041583bdc` using RFC 5649.

Corresponding `ckms` CLI command:

```bash
 ckms cc keys export -k df871e79-0923-47cd-9078-bbec83287c85 /tmp/sym_key.json  -w 027cced1-ff2b-4bd3-a200-db1041583bdc
```

Please note the presence of the `KeyWrappingSpecification` structure in the request with the unique identifier of
the symmetric key.

The response contains a `KeyWrappingData` structure with a reference to the symmetric key used for wrapping.
The encoding option is `TTLVEncoding` as specified ion the request, which indicates that the ciphertext
contains a JSON TTLV structure with the Key Material and its Attributes. Please refer to the KMIP specification for
more details.

=== "Request"

    ```json
        {
          "tag": "Get",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "df871e79-0923-47cd-9078-bbec83287c85"
            },
            {
              "tag": "KeyWrappingSpecification",
              "type": "Structure",
              "value": [
                {
                  "tag": "WrappingMethod",
                  "type": "Enumeration",
                  "value": "Encrypt"
                },
                {
                  "tag": "EncryptionKeyInformation",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "UniqueIdentifier",
                      "type": "TextString",
                      "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
                    }
                  ]
                },
                {
                  "tag": "EncodingOption",
                  "type": "Enumeration",
                  "value": "TTLVEncoding"
                }
              ]
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "df871e79-0923-47cd-9078-bbec83287c85"
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyBlock",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "KeyFormatType",
                      "type": "Enumeration",
                      "value": "CoverCryptSecretKey"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          "value": "2DCB9F6F18570EE9400372953342590B13CDAE02DC92ABDE50A873239F4EDFC64081B861B9CAC050D6AEE890CF7167AD44739974507A6D2DAB532B886B369EB00794F2ED4D80BD510556C92FF022F20D1E2E810D1466AF9B526319F8529BA9AFA34964C37BC6070BA5489970C9565785FFF29C1669251DDB6C7A189BA8D9238B2B6D717F5A4680E5458931A994DC4698D1C6E1B1D4B296CFFFA7402911933092B428F8AA9669185ACFC1ADDC7CC8026F96BFA240283F9667D03C2BC597DB1677CFBFA7CB8B88E5AC9456722477845BA6AB075F30C1DAE9BB9D95E4DA67C7E1D69E7394DC8CF6F54040B279D50C6E5C6B1FB92AAB17FD7E766C3E826603EBA9FE357199CF937AAA844B37BC8DA7C7D28E18D9C8D2A44F473D39B377BB04FD0178CE5E78385D31D19420270F7A121AEF4844977E14A5B387EB5032ABA81BFC9BEF2343C58AA1F468E4007AAAA3E7725754B1127A2F89D15DBE4F8237008B68D00F4C00862560A4A5FCB9E47C9E802A70C3AEEEAED6DE4136FFBCF31F50B5745C1975A08CC818C81655F6C5E9DAE96E7E76F5D58EB0A1FC1D9A10839E8ACB7F0327544481CEB60CACFC299C18E40D453DF9466CC9B524CDC31ABADAB2EF78E617E6571D6BE2B4F78F057F68CCB4FD732F39CC1CD6F1AFF80804CF27765A777832E614FC01D6E9967328CA7938D9BE8560B19C1A85C3C99DA43AEE7850FEC158541C968E8287142C306F9E18DD46AF5C8774E91C1786208A595DDDEBA26B28F5F06FE6AD0F2773E65082FA354A293C4924508DD0CBD469711E71F455A83929E0BD5C4A6461CB5F2ED57B7A55E3EA74E99525917FF76488CD7B1CF24515FE77FBAB4D4C0F686A921D50D643C0E7058357B2313DF8D2B376B261DE966E33BF436AAF7EEB200E1E577E0C0B3D6C3C9B3F7199202AC9D7160B15D3DFEC1F395DCCA876AD50201CC85CB07B28160D60DFB6EAF8EC9F591642B946BBD3D9FBBD41565A42383848EE0D2C47AA2715C1AE1E937795098DBF9A161A25DD2705F84261041F4395B93BA49916B6F7A1D386FF0B1C31AF06A15B96D4E43E60510C1E6D9C613E2DDC7E9B0821E99AC1FC82235AFC472FBB4B49923D139F7801DAAA73022B6BF53E0E067A7F6BDB128BB3DF47B9DFC72B1DDE87A0D67EE446FD248BBD4E9CF9983CD0E38D1430672145EF2B84F8CA1C3B04E4CD3C0405BD82523F23057F89BBDBAA04F2241AF87A0CFA76917D34F69B021BEE26BE5DD4F31D446684948A366C23696E64A3B56A9B67541AE575BF4C18933EEB3EAC634590BE9E0995E355FFB66ED1C3D284F20D0246EFD286D98EC337DA91AB9BF62FDAFC80F76D94D9F132CDF75A70F39DE697B1619011E9C7DD5BE305CA699480B276C8B62356626196F00EDBE250512A39E3750DDA8B62B329F20B339630F5BAD63A5B9203CC05170A7BD2F40929886DDEB14EF55C3ED2D7228034F8A632B1E7A7D44272A87E131AF2FE09640496A6D74E88F3D67AA17732884F3EED6C9DF4EC4D41A81F47B0124DA017D4D7AF079F79A1795541A49FB3D8A7F17CA1167FF7B4467813F02A7C97E53BAFDA269EB6D85F6086C17B60763DBD753E1FCC642CCEE072C9AB41FC433CBBEA9E3B97389DD205E05A2BA5DF147032B8C721119A831A29F474F7D9D6CF14F887CC43F5343F94CEBEDA7228BB3A6F7429A58FFF595CA055522B18C32DCB7377E953B2099116517FD32DDD1566C8C0B759C7CEBEE1B8CC3C21B7A8735D791D1F964F8C41A3B02EB9BA47537D03B6226003CDB05C0315B8B9B5D36C44F7FFC242B8783D27D6F2C014396CC88B0AA6B03C798199B1D309A1130A1DFEE0862F8619C127FA922EC83816E0A1FDF24EF7F27EEF5D92E5035D4E5A1BD9F656D1A3F384E617DA90677FFDE819CD618B9A13DA1E4FBD6AE8B61AC1CEE8A5C7D93C4BB4BB97325E75E5264CFD22B0A58BA7D55CB84DD5DADDFBEEDAC39A96D7498017DF1564BC853643764D73EFB370B6E3CB6A876678657A1499B7AFE47F92AD3B946099F7A86E2EDB731CFC7E0560A618EE56944A90BCE1E5928A3B506AD02A197EA71FCF3E290FF2DDFBECC6F79CA8405D87F65D73F3F6E39AFD8BFEA8AA35F246CE8BC85226BF3D7FD70D8C56589A48D38AF721B97FC58B0D"
                        },
                        {
                          "tag": "Attributes",
                          "type": "Structure",
                          "value": [
                            {
                              "tag": "CryptographicAlgorithm",
                              "type": "Enumeration",
                              "value": "CoverCrypt"
                            },
                            {
                              "tag": "KeyFormatType",
                              "type": "Enumeration",
                              "value": "CoverCryptSecretKey"
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
                                      "value": "ParentLink"
                                    },
                                    {
                                      "tag": "LinkedObjectIdentifier",
                                      "type": "TextString",
                                      "value": "b652a48a-a48c-4dc1-bd7e-cf0e5126b7b9"
                                    }
                                  ]
                                }
                              ]
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
                                      "value": "5B224D79557365724B6579225D"
                                    }
                                  ]
                                },
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
                                      "value": "cover_crypt_access_policy"
                                    },
                                    {
                                      "tag": "AttributeValue",
                                      "type": "ByteString",
                                      "value": "5365637572697479204C6576656C3A3A436F6E666964656E7469616C20262620284465706172746D656E743A3A46494E207C7C204465706172746D656E743A3A485229"
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "tag": "CryptographicAlgorithm",
                      "type": "Enumeration",
                      "value": "CoverCrypt"
                    },
                    {
                      "tag": "CryptographicLength",
                      "type": "Integer",
                      "value": 1832
                    },
                    {
                      "tag": "KeyWrappingData",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "WrappingMethod",
                          "type": "Enumeration",
                          "value": "Encrypt"
                        },
                        {
                          "tag": "EncryptionKeyInformation",
                          "type": "Structure",
                          "value": [
                            {
                              "tag": "UniqueIdentifier",
                              "type": "TextString",
                              "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
                            }
                          ]
                        },
                        {
                          "tag": "EncodingOption",
                          "type": "Enumeration",
                          "value": "TTLVEncoding"
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

### Example - An EC private key in PKCS#8, linked to a certificate

Exporting in PKCS#8 an EC private key `bf614d45-5a3e-49b9-95c0-5586d3c0d17b` which was imported as part of a PKCS#12
container.

Corresponding `ckms` CLI command:

```bash
  ckms ec keys export /tmp/pkey.pem -f pkcs8-pem -k bf614d45-5a3e-49b9-95c0-5586d3c0d17b
```

Please note:

- the presence of the `KeyFormatType` in the request set to `PKCS8`
- the presence of a `Link` structure in the response, which links the private key to the certificate

=== "Request"

    ```json
        {
          "tag": "Get",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
            },
            {
              "tag": "KeyFormatType",
              "type": "Enumeration",
              "value": "PKCS8"
            },
            {
              "tag": "KeyWrapType",
              "type": "Enumeration",
              "value": "AsRegistered"
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyBlock",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "KeyFormatType",
                      "type": "Enumeration",
                      "value": "PKCS8"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          // the key material is the PKCS#8 DER encoding of the private key
                          "value": "302E020100300506032B656E042204207D282BE753D7DCAF8E741BBA62C1E8A88DB99161863D89C41275358774B37090"
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
                              "value": 253
                            },
                            {
                              "tag": "KeyFormatType",
                              "type": "Enumeration",
                              // the format is PKCS#8, as requested
                              "value": "PKCS8"
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
                                      "value": "PKCS12CertificateLink"
                                    },
                                    {
                                      "tag": "LinkedObjectIdentifier",
                                      "type": "TextString",
                                      // The unique identifier of the linked certificate
                                      "value": "d2f4e937-dda9-4a86-bbe8-c866646a612f"
                                    }
                                  ]
                                }
                              ]
                            },
                            {
                              "tag": "ObjectType",
                              "type": "Enumeration",
                              "value": "PrivateKey"
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "tag": "CryptographicAlgorithm",
                      "type": "Enumeration",
                      "value": "ECDH"
                    },
                    {
                      "tag": "CryptographicLength",
                      "type": "Integer",
                      "value": 253
                    }
                  ]
                }
              ]
            }
          ]
        }
    ```

### Example - A certificate in X509

Exporting in X509 a certificate `d2f4e937-dda9-4a86-bbe8-c866646a612f` which was imported as part of a PKCS#12.

Corresponding `ckms` CLI command:

```bash
  ckms -- certificates  export /tmp/cert.x509 -f pem -k d2f4e937-dda9-4a86-bbe8-c866646a612f
```

The conversion from DER to PEM is done by the CLI.

Please note:

- the presence of the `KeyFormatType` in the request set to `X509`
- the presence of a `Link` structure in the response, which links the certificate to the private key
- the presence of a `CertificateValue` structure in the response, which contains the X509 DER encoding of the certificate

=== "Request"

    ```json
        {
          "tag": "Get",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "d2f4e937-dda9-4a86-bbe8-c866646a612f"
            },
            {
              "tag": "KeyFormatType",
              "type": "Enumeration",
              "value": "X509"
            },
            {
              "tag": "KeyWrapType",
              "type": "Enumeration",
              "value": "AsRegistered"
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "Certificate"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "d2f4e937-dda9-4a86-bbe8-c866646a612f"
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "CertificateType",
                  "type": "Enumeration",
                  "value": "X509"
                },
                {
                  "tag": "CertificateValue",
                  "type": "ByteString",
                  "value": "308201443081F7A003020102021004802E89DDF1412B9D8341571667EC9D300506032B657030133111300F06035504030C084B6D735375624341301E170D3233303930383133353033345A170D3234303330393034353033345A30143112301006035504030C094D7920736572766572302A300506032B656E032100124EAAD397D23A8A09847739EFD27E8232846E34AB4B73BDE0D3BC3BB30E842EA360305E301D0603551D0E04160414655E04099884AF3CCA3E3B11D908BB8FD27270BC301F0603551D230418301680148AA1C25FAA8B071496FE96AA8578D4DC6175AB71300C0603551D130101FF04023000300E0603551D0F0101FF0404030203E8300506032B65700341002FDDFC5EE8D0DD0626989F25EE8CEBDC4D28CBEB5AA397D650766426FF30D820662C178622CF2AB101A509ECF11E5F7D6D603181E3C91FBAA2EC2716651D2A0F"
                }
              ]
            }
          ]
        }
    ```

### Example - A PKCS#12 container

Export a PKCS#12 container using the unique identifier of the private key.
The Private Key must have a link to:

- either a certificate with a link of type `PKCS12CertificateLink` or `CertificateLink`
- or a link to a public key with a link of type `PublicKeyLink`, the public key having a link to a certificate with a
   link of type `CertificateLink`.
- for intermediate certificates to be included, the certificate must have a link to a certificate with a link of type
   `CertificateLink` to its issuer.

Corresponding `ckms` CLI command:

```bash
  ckms certificates export -k bf614d45-5a3e-49b9-95c0-5586d3c0d17b -f pkcs12 -p secret  /tmp/exported.p12
```

Please note:

- the presence of the `KeyFormatType` in the request set to `PKCS12`.
- the presence of a `KeyWrappingSpecification` structure in the request with the the secret used to seal the PKCS#12
  container.
- the `EncodingOption` is ignored in this case.

=== "Request"

    ```json
        {
          "tag": "Get",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              // The unique identifier of the private key
              "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
            },
            {
              "tag": "KeyFormatType",
              "type": "Enumeration",
              // The format is PKCS#12
              "value": "PKCS12"
            },
            {
              "tag": "KeyWrappingSpecification",
              "type": "Structure",
              "value": [
                {
                  "tag": "WrappingMethod",
                  "type": "Enumeration",
                  "value": "Encrypt"
                },
                {
                  "tag": "EncryptionKeyInformation",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "UniqueIdentifier",
                      "type": "TextString",
                      // The PKCS#12 secret
                      "value": "secret"
                    }
                  ]
                },
                {
                  "tag": "EncodingOption",
                  "type": "Enumeration",
                  "value": "TTLVEncoding"
                }
              ]
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "GetResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              // The unique identifier of the private key
              "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
            },
            {
              "tag": "Object",
              "type": "Structure",
              "value": [
                {
                  "tag": "KeyBlock",
                  "type": "Structure",
                  "value": [
                    {
                      "tag": "KeyFormatType",
                      "type": "Enumeration",
                      // The format is PKCS#12
                      "value": "PKCS12"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          // The PKCS#12 container bytes protected with the secret
                          "value": "308204660201033082042C06092A864886F70D010701A082041D04820419308204153082036706092A864886F70D010706A0820358308203540201003082034D06092A864886F70D010701301C060A2A864886F70D010C0106300E0408A1CE7477CB52D0FB02020800808203201250CC796DD733F83D1412EA850360420552BBD1D6086F55F14694F711BC1AA4940942B651FD196A33F157EA4642E8344C241751E439C3ECF5EFEDAE4602BCF0B624874F5F402F69C0C08BB241760017279B76EA3784CFF3C5CF8F69790D84DDB1702D345F19FBED027CDE104381D4F52CDE37AD8407D36428F371E6A0295006F80651D2A4394B2C7C468A1EDD0F500E51B1A3353CD3E4AB954AF1BE23A9203CEE4FE3D712A6191DAED8F9E391273A7EA1EF9549E9E48176FED98E6B2554A4871638DA1733443817012A5F80750203FDA0E6DED6C8DA27E151682362C184C53425547A60275A3638D2DCA0726FC87C46F4DA9418064E62F14D09085860DD1D13E096E0AB05BBE5CC2162E2973EC154E86819EDE3CCA8A4140EB003543BEDE901DB2F8A5FCBB2E80FEB2B2B2B22B2B4CB4D663D07178F4E93568261759DA834108EA7D1F8BF06947799EAED802436F3C2EAEE8D3218B98B1153B4926C052992C01EB75B3BC032C1A232FACFFC472403DC86C6DD8DF22D700A38DC86EB58B246BFDE3D737F1CEC218383DDDB986657E3AF57D4AC0299ED99D8468CED2D97F14375C4A9AA438086629AA8A651A01701894CF06AA28137A68A70977995E4CF9DBAC4373D483C7E2E1D889E2BEA47E92715F8D540A5C534C43E5E953532264DA581F3DD059E8974AE072C50368F44E93F29D8A34E56DD40338CC69271B14FA7E7CF68FB9D586A26337A449F7CC5222F2F4EFE411691B30E8E25532C1BB6EB9D28EE5EDAF6E54D5C29C38D678AE158425F7959F89B06B10010D7EC1B3BF67C340FE5621D679CA48F2B1AFCF603CAB6581883A32A8733BBE738A7A1F82CBEC590BF69475A3331EB5AC2684EAB6D737E3A1DFACA734A4AC96AEA0E883F9C7B720E68016EEABDC5C88C4B3F405F46B7290CE8BA5258B92BA14122A87624E172CECCF4766066E1AFAF8EF06D1896994265A27080BF3AAB7B73638482A8EF6527B8A8245E514238C8E80A5F9750A663D5468DC5D8460D4793AF77B1D39B1D2A0099114FA8FF8E2D80B10E9F91A295CED84AE3C30C73A27D1CA90CBED4582A7ED0015BAA58DA9850202D1903086802FC5705F5BE0C4FA9F1AD11B82A340ED3DC8A835D08396C3081A706092A864886F70D010701A08199048196308193308190060B2A864886F70D010C0A0102A05A3058301C060A2A864886F70D010C0103300E04089971B59CB1424F9502020800043818AC3DDA45F299AC2D5441F538E49BD14E2AF1DF51A28DC926616D4E16C3100C2B2D9111219688C5BD81F70DAB647B0C8A6F6844150F05033125302306092A864886F70D0109153116041460854FAEF5E61527293E6551F170EF7145957FC430313021300906052B0E03021A0500041459585C94B586A45D6D75323D09976AC88DBEE3CA0408B40773C6DA0DF8BD02020800"
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
