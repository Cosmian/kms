### Specification

This operation requests the server to Import a Managed Object specified by its Unique Identifier.
The request specifies the object being imported and all the attributes to be assigned to the object.

The attribute rules for each attribute for "Initially set by" and "When implicitly set" SHALL NOT be enforced as all
attributes MUST be set to the supplied values rather than any server-generated values.

The response contains the Unique Identifier provided in the request or assigned by the server. The server SHALL copy the
Unique Identifier returned by this operation into the ID Placeholder variable.

### Implementation

Key unwrapping on import is supported for all keys. Please check the [algorithms page](../algorithms.md)
for more details.

For the list of supported key formats, please check the [formats page](./formats.md).

### Example - A NIST P-256 EC private key in SEC1 format

Importing a NIST P-256 EC Private Key in SEC1 format.

Corresponding `ckms` CLI command:

```bash
ckms ec keys import crate/cli/test_data/certificates/openssl/prime256v1-private-key.pem --key-format pem
```

The conversion from PEM to DER is done by the `ckms` CLI.

In the JSON TTLV requests, please note:

- the empty `UniqueIdentifier` which requests the server to generate a new `UniqueIdentifier` for the imported key.
- the empty tags `[]` in hex
- the `KeyFormatType` set to `ECPrivateKey` which indicates to the server that the key is in SEC1 format.

=== "Request"

    ```json
        {
          "tag": "Import",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
            // Ask the server to generate an identifier for the imported key
              "value": ""
            },
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "ReplaceExisting",
              "type": "Boolean",
              "value": false
            },
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
                          // [] in hex (i.e. no tags)
                          "value": "5B5D"
                        }
                      ]
                    }
                  ]
                }
              ]
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
                      // This is SEC1
                      "value": "ECPrivateKey"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          "value": "307702010104204CC0D4B807CED6BB2CCFE44D467D6A2A5D706B0E11E9352CF5CA8D3998790B83A00A06082A8648CE3D030107A14403420004A8D465338FB81879378BC9730A07A2BA455009E1B4606A58136C4A73C40B4BE7DDFE9D7959BC16E6BF8D6F2EF4BA4DB43A3DA29FA1A9D2ECA5AD30F129A0A5A4"
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
          "tag": "ImportResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "927adccb-f59a-4cc9-a9e3-1eeb958c601f"
            }
          ]
        }
    ```

### Example - A RSA 2048 private key in PKCS#8 format

Importing a RSA 2048 key in PKCS#8 format with tags `MyRSAKey`and `2048`.

Corresponding `ckms` CLI command:

```bash
  ckms ec keys import crate/cli/test_data/certificates/openssl/rsa-2048-private-key.pem --key-format pem --tag "MyRSAKey" --tag "2048"
```

The conversion from PEM to DER is done by the `ckms` CLI.

In the JSON TTLV Request, please note:

- the empty `UniqueIdentifier` which requests the server to generate a new `UniqueIdentifier` for the imported key.
- the tags `["MyRSAKey","2048"]` in hex
- the `KeyFormatType` set to `PKCS8` which indicates to the server that the key is in PKCS#8 format.
- the `KeyMaterial` which are the hex-encoded DER bytes of the PKCS#8 structure.

=== "Request"

    ```json
        {
          "tag": "Import",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              // Ask the server to generate an identifier for the imported key
              "value": ""
            },
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "ReplaceExisting",
              "type": "Boolean",
              "value": false
            },
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
                          // ["MyRSAKey","2048"] in hex
                          "value": "5B224D795253414B6579222C2232303438225D"
                        }
                      ]
                    }
                  ]
                }
              ]
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
                      // This is PKCS#8
                      "value": "PKCS8"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          // PKCS#8 DER bytes in hex
                          "value": "308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100B466EEF95ECB9CEC2F9AFA71F280C3F7671BD18C21819E08521D890CADF4D52EB02B33D2CEC25B45124F4977FC5EB43918FD0717697EBF09B0AD3143915DD233A248DBA42550ECE7530AA98C318F425915E1300600B873B24EB33715A93A96F7AC4198C1EFBD111B7D0D7100FCEB90A3B2549F4D9CDF1C08E0E14098ED07F5442FFFA9775F488778CE967AFB662FBC8FE9E353E778AA49E1976F818CC8C597D9DBFAAD219DA1B5B36037B3146DBB031AA43552B18D1B03AD789BE60B19FCD685ED774BC11E9E2C8D076CEBAB5BD21FB1EB80EDCCE55C47A8BB607A6B3311E9CFBC76E162C4F98FD30E87D39ED0A8BC07CA46C2653A2B04DD47998CDDD2744E5302030100010282010018572D163B6A98952B852B1675C456EC8A1E70430A804D1CCD4B8BE2C893D8B1B0765BCB2D377F0E0E3EE1684D864FA5C68FD94598E7CF89D4AB4192DEC9BC635819A17CFFC5EFF8F434E39475596177D8A26612E14501E344881CBE10F3C54BCC939B334B90047F637B8D4C3753E75396EBA104DD4E231FB58BDEE5E351680F9D5E8F0F555BDF09CECA4E83AE6CCDC0F6E8E07AA0A2EC96ABA1B57F53667B05957B0BE4CB9564CFEC672981CB1BB57BF4785563B87A6AC3354C68B83CD73C4896DB526A5D037224EBEAECDF01EC6F94B637FA2F3128EB1588294942601ECE5B0AEE98E222BD8779ED931734FE27F0C4ADACB586CCFE649FAA0273F333CC43CD02818100EF9732DA98D3AB9F561B602F74AAEFFEBAA4F5D8A3AC93BF560DC097AC853FCD246433D30FC294D81F6FF05B2DFD286155DAF4CFB3666DDA580A992DAE649DAA6B407FD240F07E87AF6DEEA93525EED90799888B488980470F70F749AC8C440B776D0CAF327706638AD46923D14FD5E5D25CDA0DE14FA9E5869F71104D6B9E7502818100C0C1F7B91012BB6794FE901039F0B93C08DFA0D1AB6308A444B34304EBAD516EB76CBE976551F38DA4B78CF67675882A4293765BDAA824CF7DF9912BB77D9CC986A5692CF06A520C0F00148110692EF25814420FB496C8FD60C1402D487980D457FB9B54004D58F19ACDA3317734EA39CFB07DE3446200E283AB6F68B82230A702818020E24CBD8A0A4B5CF4318FB313BD3E7164E6AD438DBB6B0FF0DCB4595CF970F7540E58BA984829ABBC2CDDFD75C3705E63AD48BA9531F2D3EC0F90549FC1F98DE16899E29EBD2370B6184D9075D5FE0155B4B1F40401B3548D7F00C1E0E7E392FB5241526E87BD9DBDF94770FE128A1620185469614A50D44AF4E94CC68385DD028181008129B8A06697D6C21B01D5713A12075DA6288BAFD3A361E8092D01ECAB2C11541A4F210B7BD645589596753BB5B71E0E0B5C9AC4042A05B890168A637BEA0D04B157E7B938445644444CEE706999C1DE9C8CBE939D94288C38A86623B1DBD12AF8E5DD7895573F116E84FB24AB5766D8644644A4E46EB35F1591EBEE84EC4C2302818042F72AC26114C103F011407A8189128E3C2A2CC59CEB559DF3DA198EA1D6A0023E98B7FDCBFEF61D82AC6176981CBD4B4B239DF39189DC15B246DE13B879AC82490C065BA3A007E5413F27CD998546BE17F30AD6A40E4A891CA84CD9D006239BB47E06024DA1DE35B791A79A57CBC5C501B16B1511138DCEB97F111E548F076D"
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
          "tag": "ImportResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "8623605d-625b-4b4f-99c9-a2802e415609"
            }
          ]
        }
    ```

### Example - Covercrypt user key with unwrapping on import

Importing a wrapped Covercrypt user key after unwrapping it with symmetric key
`027cced1-ff2b-4bd3-a200-db1041583bdc` using RFC 5649.

Corresponding `ckms` CLI command:

```bash
ckms cc keys import /tmp/sym_key.json  -u
```

**Note**: the `-u` flag is used to indicate that the key should be unwrapped on import; the JSON file (obtained using the
`export` command) contains the wrapped key details.

In the JSON TTLV request, please note:

- the `KeyWrapType` set to `NotWrapped` which indicates to the server that it should look into the
   `KeyWrappingData`structure to see how to unwrap the key.
- the empty `UniqueIdentifier` which requests the server to generate a new `UniqueIdentifier` for the imported key.

=== "Request"

    ```json
        {
          "tag": "Import",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": ""
            },
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              "value": "PrivateKey"
            },
            {
              "tag": "ReplaceExisting",
              "type": "Boolean",
              "value": false
            },
            {
              "tag": "KeyWrapType",
              "type": "Enumeration",
              "value": "NotWrapped"
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
                          "value": "5B5D"
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

=== "Response"

    ```json
        {
          "tag": "ImportResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "8bfcbfba-77d9-4850-874a-b7c7511b03ae"
            }
          ]
        }
    ```

### Example - A PKCS#12 container

Importing a PKCS#12 container containing an EC private key, a certificate and an intermediate certificate.

Corresponding `ckms` CLI command:

```bash
  ckms certificates import crate/cli/test_data/certificates/p12/output.p12 --tag "MyPKCS12" -f pkcs12 -p secret
```

In the request, please note:

- the empty `UniqueIdentifier` which requests the server to generate a new `UniqueIdentifier` for the imported
  private key. The server will also generate unique identifiers for the certificate and the intermediate
  certificate but the latter are not returned in the response. To recover these identifiers, use the `Get Attributes`
  operation on the private key and then on the certificate.
- the tag `["MyPKCS12"]` in hex.
- the `KeyFormatType` set to `PKCS12` which indicates to the server that the key is in PKCS#12 format.
- the `KeyMaterial` which are the hex-encoded DER bytes of the PKCS#12 structure.
- the `LinkType` set to `PKCS12PasswordLink` which indicates to the server that the password is in the `LinkedObjectIdentifier` field.

=== "Request"

    ```json
        {
          "tag": "Import",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              // Ask the server to generate an identifier for the imported key
              "value": ""
            },
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              // PKCS#12 bundles are imported as private keys
              "value": "PrivateKey"
            },
            {
              "tag": "ReplaceExisting",
              "type": "Boolean",
              "value": false
            },
            {
              "tag": "Attributes",
              "type": "Structure",
              "value": [
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
                          "value": "PKCS12PasswordLink"
                        },
                        {
                          "tag": "LinkedObjectIdentifier",
                          "type": "TextString",
                          // The PKCS12 password
                          "value": "secret"
                        }
                      ]
                    }
                  ]
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
                          // ["MyPKCS12"] in hex
                          "value": "5B224D79504B43533132225D"
                        }
                      ]
                    }
                  ]
                }
              ]
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
                      // This is PKCS#12
                      "value": "PKCS12"
                    },
                    {
                      "tag": "KeyValue",
                      "type": "Structure",
                      "value": [
                        {
                          "tag": "KeyMaterial",
                          "type": "ByteString",
                          // PKCS#12 DER bytes in hex
                          "value": "308204660201033082042C06092A864886F70D010701A082041D04820419308204153082036706092A864886F70D010706A0820358308203540201003082034D06092A864886F70D010701301C060A2A864886F70D010C0106300E04082A727ACADC7F30FE0202080080820320C807EF330DE2F0D9B5E4B47E457DBCAE52DB41BB85E627645E9C60B51FB4FD148D2DC1C262F64212DFFB07ED5D741E8CD4AED9F684AA20A1AA8CBA372437A5183967E0EA69F7417AE5AF6B18D45864A6508B95DA6302F3892A4FB68BB29580DCC70EE91AB124D029E029E60C04CA8E1037D741E865C7968AD77BB350CE5D91F7482410E8AB3579E3C3D12530B4F402A010BB10E4C33D50ADA3FE2D8105AF8B489D5F446C976F913C48F7232A3448D79B8E6BCE2B2AE72369713017077F6732CCE794A1EFD46F59C3CB5F03978B7DF613FA2B7E9C872967C92F059A857BA935C8A235235A29E65789ADB84B7F907F2B01B11E1EEF69967A187831C6DCA81C3B4140BC20421BCAA0114FD6F2692FDDBD8569D1DE14B6D1A58C85D15F2C9FF7C1A00FE77B10D1278ED6E9AF358E7D169724A0420D4D93ACBB531AD58EA95E65A31F95063BB1C6ED080D16EA85F0E041215BF5FC3FA7C301C8CFCC73BADF46DE1E7AD7AA599ECFCE60D12474A93CBB8E869A65822466DBA2E892617C7D1626EEEED90586B70C9354DF4F5451E4E14BE38D4E7893D7F118255E9F9CBDCF290E6AEA97EBA4599587FC9BD652F346E47A697FD7F497ABB7EE1B1D53A5A10ADD99AC3F635CBE440B8D34C20FF6CEB7D8F1FF4FF4A8F0BF3158B901A42631BFC8C11E0E607344BEE46BAAFAB049FA9AD3F8752AFF90ED26102DE1D905FD389E530F34534FD206B691A82C4E1B6BD180F2F2AE0C0FF7FC943B608A247EC5C49FAB7419222C17638AEA5B5DC225CD898CC6EDD7B98E6FF73CFE9C94795B7BAE7F53DE1BC0FA2C875F75D056B01A341358283294FBE6F5E76B0E03BDC7E497F69E31FC91895940CB654E5A0F669F58C820A2486BC35FA0BC17AF93959E9CD4CAAA0E1141E7E7A12B80F409D2B8B2E36B0E6637189A4180CE6E135702C4C6AB16FB96228FFE58AC92842845FA8A73B48571FFCCC3F7C513B94B72E69C115AC22D7891EE1A5518032C4661654486DC0F2808CEC195E80A0BA6501F0C6E1A454C5A6CD17137F10226EEB9182D7B848AAE0C5FF19FC5ED8EF1E19B45ECA1CAA45BDC7B913BEBB38D4F3B35BE8F5A70A9F58DFEEEBB68BDF83844DE4FE00CDA4745EF2194FF417D943081A706092A864886F70D010701A08199048196308193308190060B2A864886F70D010C0A0102A05A3058301C060A2A864886F70D010C0103300E04086CA064C6D55C2211020208000438FF5E786E0DB3C6D85C358321EF8E5BB0E8A057ACFC33E52281897F152239736B1F2DB061D712E8A83747A767C168737A515EFE1BE7EDAE3E3125302306092A864886F70D0109153116041460854FAEF5E61527293E6551F170EF7145957FC430313021300906052B0E03021A050004149CF1C7AF502B81AB981D5786E4800099B9D37D960408B970C0A9A2BDB46102020800"
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
          "tag": "ImportResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "bf614d45-5a3e-49b9-95c0-5586d3c0d17b"
            }
          ]
        }
    ```

### Example - A X509 Certificate

Importing a X509 certificate.  The certificate must be imported an X509, DER encoded.

Corresponding `ckms` CLI command:

```bash
  ckms certificates import --tag "MyImportedCert" crate/cli/test_data/certificates/ca.crt -f pem
```

The conversion from PEM to DER is done by the CLI.

In the JSON TTLV request, please note:

- the empty `UniqueIdentifier` which requests the server to generate a new `UniqueIdentifier` for the imported
  certificate.
- the tag `["MyImportedCert"]` in hex.
- the `ObjectType` set to `Certificate` which indicates to the server that the key is in X509 format.

=== "Request"

    ```json
        {
          "tag": "Import",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              // Ask the server to generate an identifier for the imported certificate
              "value": ""
            },
            {
              "tag": "ObjectType",
              "type": "Enumeration",
              // this is a certificate
              "value": "Certificate"
            },
            {
              "tag": "ReplaceExisting",
              "type": "Boolean",
              "value": false
            },
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
                          // ["MyImportedCert"] in hex
                          "value": "5B224D79496D706F7274656443657274225D"
                        }
                      ]
                    }
                  ]
                }
              ]
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
                  // X509 DER bytes in hex
                  "value": "3082033030820218020900C03CBFDC0BD87789300D06092A864886F70D01010B0500305A310B3009060355040613024652310C300A06035504080C03496446310E300C06035504070C0550617269733111300F060355040A0C0841636D6554657374311A301806035504030C1141636D65205465737420526F6F74204341301E170D3233303531393135323934355A170D3333303531363135323934355A305A310B3009060355040613024652310C300A06035504080C03496446310E300C06035504070C0550617269733111300F060355040A0C0841636D6554657374311A301806035504030C1141636D65205465737420526F6F7420434130820122300D06092A864886F70D01010105000382010F003082010A0282010100D61FF874D90172D96968F8DEA453A9D2ACD29886EAC934A18ED1172136FFE284EA702B14FA3BD2900782BCE489A6CF2FC8063F1C8BC13C52F92A3B72B44A343786B1A1DC7A3C49CA1EB24AAFF809F5AE3BB64120553B9B40E2E104966C9C8C0CF2DEBDA167FA804BDB1FBC66CDA82052F9918771FDE318D74E4894D51B808A06A10330C3E985EC2B0067C60F955AD74D64FD4667ABA76D9DC17F681B36391698BF2A3303665C19E2C20A9CADD174A49FD236E89E7541F3AACDC8453ECE094D1C886761A39CBBF809F5F27396E1C9CF431280C07670E87A3BCC9ED6C38037F53E5E006FE2D952D48D9B57D765061A5F8C2CA30CCE394DD2ED88EB6856623239190203010001300D06092A864886F70D01010B05000382010100C48C6AC67FD80062816E065637B64B17D8821299A8718CF04E7D3998C761E72C3030F27DD3C955754BFE25F3D750D15C6ABFFC887FD63B27A1C345B8F9C78BA886196866C49180C3BA37BF20D918B0EAD6051C1AEAB3C98798C43580AA10E7909F7F7F122E9349CC74FE6EFCF947C761945C3BABF68973773CC7B36FBF346D4D4286BB88BB45FA5388870F58BD192F6ED6B8541C269C7F4D77D62DE860E981CDB6D5E99579164C048C80898BF6B53E731AB97997FF48DA5FC8BB6357574CDB58BE6922ECA9CD644E7442177B66032665D186A9F6027ECF6295235922EF045285D9118182E12D608EAA21E5879B08B3BCA894D10E947625058B90796FC7FCDD57"
                }
              ]
            }
          ]
        }

    ```

=== "Response"

    ```json
        {
          "tag": "ImportResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "fc0a018d-5581-44e5-baae-052c2ac98757"
            }
          ]
        }
    ```
