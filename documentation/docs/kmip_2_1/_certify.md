#### Specifications

This request is used to generate a Certificate object for a public key. This request supports the
certification of a new
public key, as well as the certification of a public key that has already been certified (i.e.,
certificate update).
Only a single certificate SHALL be requested at a time.

The Certificate Request object MAY be omitted, in which case the public key for which a Certificate
object is generated
SHALL be specified by its Unique Identifier only. If the Certificate Request Type and the
Certificate Request objects
are omitted from the request, then the Certificate Type SHALL be specified using the Attributes
object.

The Certificate Request is passed as a Byte String, which allows multiple certificate request types
for X.509
certificates (e.g., PKCS#10, PEM, etc.) to be submitted to the server.

The generated Certificate object whose Unique Identifier is returned MAY be obtained by the client
via a Get operation
in the same batch, using the ID Placeholder mechanism.

For the public key, the server SHALL create a Link attribute of Link Type Certificate pointing to
the generated
certificate. For the generated certificate, the server SHALL create a Link attribute of Link Type
Public Key pointing to
the Public Key.

The server SHALL copy the Unique Identifier of the generated certificate returned by this operation
into the ID
Placeholder variable.

If the information in the Certificate Request conflicts with the attributes specified in the
Attributes, then the
information in the Certificate Request takes precedence.

#### Implementation

The KMIP implementation does not:

- specify how the signer is selected and whether self-signing is allowed
- specify how the certificate extensions are provided
- and only supports Certificate Signing Request (CSR) and certifying public keys

Cosmian has extended the specifications and offers 4 possibilities to generate a
certificate

1. Providing a Certificate Signing Request (CSR)
2. Providiong a public key id to certify as well as a subject name
3. Providing an existing certificate id to re-certify
4. Generating a keypair then signing the public key to generate a certificate
   specifying a subject name and an algorithm

The signer is specified by providing an issuer private key id
and/or an issuer certificate via the Links in the attributes of the request. If only
one of this parameter is specified, the other one will be inferred
from the links of the cryptographic object behind the provided parameter.

If no signer is provided, the certificate will be self-signed.
It is not possible to self-sign a CSR.

When re-certifying a certificate, if no certificate unique identifier is provided,
the original certificate id will be used and the original certificate will
be replaced by the new one. In all other cases, a random certificate id
will be generated.

#### Supply X509 extensions (optional)

Specify X509 extensions for a `Certify` operation is possible using the `ckms` CLI.

The `--certificate-extensions` arg (short version `-e`) expects a path to a configuration file
written in `ini` format (roughly the same format
as [OpenSSL X509 v3 cert extension cnf format](https://www.openssl.org/docs/man1.1.1/man5/x509v3_config.html)).

The extensions may be part of a paragraph called `v3_ca`.

Example of a configuration file containing `v3_ca` parag describing extensions to add:

```ini
[v3_ca]
basicConstraints=critical,CA:FALSE,pathlen:0
keyUsage=keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:http://cse.example.com/crl.pem
```

These extensions are embedded in the `Certify` request within the vendor attributes.

Example of the corresponding `ckms` CLI command:

```shell
ckms certificates certify \
  -r my_cert.csr -k 854d7914-3b1d-461a-a2dd-7aad27043b56 -d 365 -t "MyCert" \
  -e /some/path/to/ext.cnf
```

#### Example - PKCS#10 Certificate Signing Request

Certify a PKCS#10 Certificate Signing Request (CSR) with the issuer private key unique identifier
`854d7914-3b1d-461a-a2dd-7aad27043b56`, and set the certificate requested validity to 365 days and
the tag to `MyCert`.

The corresponding `ckms` CLI command is:

```shell
ckms certificates certify -r my_cert.csr -k 854d7914-3b1d-461a-a2dd-7aad27043b56 -d 365 -t "MyCert"
```

Note: the `ckms` client converts the CSR from PEM TO DER before creating the JSON TTLV and sending
it to the
server.

=== "Request"

    ```json
        {
          "tag": "Certify",
          "type": "Structure",
          "value": [
            {
              "tag": "CertificateRequestType",
              "type": "Enumeration",
              "value": "PEM"
            },
            {
              "tag": "CertificateRequestValue",
              "type": "ByteString",
              // the PKCS#10 Certificate Signing Request DER bytes encoded in hex
              "value": "2D2D2D2D2D424547494E20434552544946494341544520524551554553542D2D2D2D2D0A4D494944704443434167774341514177587A454C4D416B474131554542684D43526C49784444414B42674E564241674D41306C6B526A454F4D417747413155450A427777465547467961584D784544414F42674E5642416F4D42304E7663323170595734784444414B42674E564241734D4131496D524445534D424147413155450A4177774A5647567A6443424D5A57466D4D4949426F6A414E42676B71686B6947397730424151454641414F43415938414D49494269674B4341594541773045470A575355754F4E59526C5A3077506139524A7057416C577351515A5050675350786E354D5777464E4F383671676856666378314C387169515079315147687172320A764F766D577A366D752F59772F5663366E44644744694B54555564537341305167566474643770366B71317341393071364C30416E63384D384D46392F6F536F0A7145642F6C4F436774744F6D55667842566C314B6D7146434146464854786E4B5737387954332F3438386B57373952516B6D41367733416246377361787639500A706843365A634F76514F6836644D42326E4E6C574C67537670312B3948674455635956394D53575A6D2B376C524F5468552B41676433363364355A57574F41470A495659544E5A2F6E746B69705270717251352B7356694863752F4E4F544D757733524C632F575347736D6A594E57616465304C6D2F58685032684D67416D6F350A306474792B36307970437342573269504A6652755152743342644249632B3971637946326176786C457431414446556A49726B305353516F39774A45313953440A68534A414A33782B4D31466C6D4C2B34464832726E69777555615A6F6844506938567542367A634430747732524F664471586A2F5A4B356C7A4A6D745A6B53790A5636704B54485035737558372B6A3848324A35554A496F46487A44484764674E315A724C3570773563305A6D65634B516D5756796F394854614B364641674D420A414147674144414E42676B71686B6947397730424151734641414F4341594541594236615738625549306361466443356939334F376542345530535A414745740A612F546B5133486C764456364F2B327A64735042304F4672385262355171784134776A3843536579466C7A775666497172756A48457831557150706E2B7932720A4C6C397236754C7257725A753568664C767749752B774C6A617644425662354E2B7159536548357643334A582B4652385A64787A6B5754776465464C6F4273340A434749456D46494D2F2B666E79676E6B4C455254566B6738337339534B44736838316772755438302F6135365649636D656E373470584830514641615368766F0A7A52486F7670766A5631735A416265595365796B69564E53497179734166594A33327168744173366E5367796751637A546773756A4F746C63776653432B71550A497A4D623932325A654B5445427A7A3859326351394D6245714850787276664B5A675A4A43306B57342F482B736F2B5659776A684956337048705842527944640A6359637275732B434D335A416A456439585A6C39466D37454555736E346D7459486F497541394167756949425152596B473469726863524E5449377A36755A2B0A77544E724D792B47646B436B5271424256714146374E3473696931356E334E716A3535637257452F642F38316B574E36495943504448586C4F38756B4A6E4B750A30524E6A4B52656551624377596B72464C7A4F5A677342674E6C626E364263470A2D2D2D2D2D454E4420434552544946494341544520524551554553542D2D2D2D2D0A"
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
                          "value": "PrivateKeyLink"
                        },
                        {
                          "tag": "LinkedObjectIdentifier",
                          "type": "TextString",
                          // The issuer private key unique identifier
                          "value": "854d7914-3b1d-461a-a2dd-7aad27043b56"
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
                          "value": "requested_validity_days"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                          // 365 as a string in UTF-8 bytes encoded in hex
                          "value": "333635"
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
                          "value": "tag"
                        },
                        {
                          "tag": "AttributeValue",
                          "type": "ByteString",
                            // ["MyCert"] as UTF-8 bytes encoded in hex
                          "value": "5B224D7943657274225D"
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
          "tag": "CertifyResponse",
          "type": "Structure",
          "value": [
            {
              "tag": "UniqueIdentifier",
              "type": "TextString",
              "value": "b7225902-a035-45e6-a3d2-fa65c0ca7af1"
            }
          ]
        }
    ```

#### Example - Public key

Certify a public key with unique id `45e56e67-d813-468f-9116-4d1e611a1828` using the issuer private
key
`45e56e67-d813-468f-9116-4d1e611a1828`.
Set the Subject Name of the certificate to `C=FR, ST=IdF, L=Paris, O=AcmeTest, CN=bob@acme.com`, the
tag to `Bob` and
the certificate requested validity to 365 days.

The corresponding `ckms` CLI command is

```shell
ckms certificates certify -p 45e56e67-d813-468f-9116-4d1e611a1828 -k 854d7914-3b1d-461a-a2dd-7aad27043b56 \
-d 365 -t "Bob" --subject-name "C=FR, ST=IdF, L=Paris, O=AcmeTest, CN=bob@acme.com"
```

Please note the following in the JSON TTLV of the request:

- the various Subject Name fields that are set for the certificate
- the Subject Name issuer fields are ignored: they will be copied from the certificate linked to the
  issuer private key

=== "Request"

    ```json
    {
      "tag": "Certify",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          // the public key unique identifier
          "value": "45e56e67-d813-468f-9116-4d1e611a1828"
        },
        {
          "tag": "Attributes",
          "type": "Structure",
          "value": [
            {
              "tag": "CertificateAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "CertificateSubjectCn",
                  "type": "TextString",
                  // the Common Name of the certificate
                  "value": "bob@acme.com"
                },
                {
                  "tag": "CertificateSubjectO",
                  "type": "TextString",
                  // the Organization of the certificate
                  "value": "AcmeTest"
                },
                {
                  "tag": "CertificateSubjectOu",
                  "type": "TextString",
                  // the Organizational Unit of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectEmail",
                  "type": "TextString",
                  // the Email of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectC",
                  "type": "TextString",
                  // the Country of the certificate
                  "value": "FR"
                },
                {
                  "tag": "CertificateSubjectSt",
                  "type": "TextString",
                  // the State of the certificate
                  "value": "IdF"
                },
                {
                  "tag": "CertificateSubjectL",
                  "type": "TextString",
                    // the Locality of the certificate
                  "value": "Paris"
                },
                {
                  "tag": "CertificateSubjectUid",
                  "type": "TextString",
                  // the Unique Identifier of the certificate: empty => assigned by the server
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectSerialNumber",
                  "type": "TextString",
                    // the Serial Number of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectTitle",
                  "type": "TextString",
                  // the Title of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectDc",
                  "type": "TextString",
                    // the Domain Component of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateSubjectDnQualifier",
                  "type": "TextString",
                    // the Distinguished Name Qualifier of the certificate
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerCn",
                  "type": "TextString",
                    // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerO",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerOu",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerEmail",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerC",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerSt",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerL",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerUid",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerSerialNumber",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerTitle",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerDc",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                },
                {
                  "tag": "CertificateIssuerDnQualifier",
                  "type": "TextString",
                  // Ignored
                  "value": ""
                }
              ]
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
                      // the unique identifier below is that of the issuer private key
                      "value": "PrivateKeyLink"
                    },
                    {
                      "tag": "LinkedObjectIdentifier",
                      "type": "TextString",
                      // the issuer private key unique identifier
                      "value": "854d7914-3b1d-461a-a2dd-7aad27043b56"
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
                      "value": "requested_validity_days"
                    },
                    {
                      "tag": "AttributeValue",
                      "type": "ByteString",
                      // 365 as a string in UTF-8 bytes encoded in hex
                      "value": "333635"
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
                      "value": "tag"
                    },
                    {
                      "tag": "AttributeValue",
                      "type": "ByteString",
                      // ["Bob"] as UTF-8 bytes encoded in hex
                      "value": "5B22426F62225D"
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
        "tag": "CertifyResponse",
        "type": "Structure",
        "value": [
          {
            "tag": "UniqueIdentifier",
            "type": "TextString",
            "value": "974b3a79-25a8-4ace-bdd9-70f5b07695c9"
          }
        ]
      }
    ```
