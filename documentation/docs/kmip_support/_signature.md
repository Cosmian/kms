#### Specification

The Sign operation requests the server to generate a digital signature for the provided data using a specified Managed Object.

The request contains the unique identifier of the signing key, data to be signed (or already digested data), and cryptographic parameters. The signature is computed using the specified signing key and cryptographic parameters.

The SignatureVerify operation validates a digital signature against provided data using a specified verification key.

#### Implementation

The Cosmian KMS server supports signing with RSA and EC private keys. The signature algorithms supported include:

- RSA-PKCS#1 v1.5 with SHA-256, SHA-384, SHA-512
- RSA-PSS with SHA-256, SHA-384, SHA-512
- ECDSA with SHA-256, SHA-384, SHA-512
- Ed25519 (signature verification only for imported keys)

#### Example - Sign with RSA Private Key

Sign data using an RSA private key with SHA-256.

**Note**: Sign and SignatureVerify operations are available through the KMIP JSON API endpoint but not directly exposed through CLI subcommands. Use direct HTTP requests to the `/kmip/2_1` endpoint.

=== "Sign Request"

    ```json
    {
      "tag": "Sign",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "9382bfec-bd6c-46ed-8f00-90b467f77a15"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "DigitalSignatureAlgorithm",
              "type": "Enumeration",
              "value": "SHA256WithRSAEncryption"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "48656C6C6F2C207369676E61747572652074657374"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": true
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": true
        }
      ]
    }
    ```

=== "Sign Response"

    ```json
    {
      "tag": "SignResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "9382bfec-bd6c-46ed-8f00-90b467f77a15"
        },
        {
          "tag": "SignatureData",
          "type": "ByteString",
          "value": "3A4B5C6D7E8F901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12"
        }
      ]
    }
    ```

#### Example - Signature Verification

Verify a signature using the corresponding public key.

=== "SignatureVerify Request"

    ```json
    {
      "tag": "SignatureVerify",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "9382bfec-bd6c-46ed-8f00-90b467f77a15_pk"
        },
        {
          "tag": "CryptographicParameters",
          "type": "Structure",
          "value": [
            {
              "tag": "DigitalSignatureAlgorithm",
              "type": "Enumeration",
              "value": "SHA256WithRSAEncryption"
            }
          ]
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "48656C6C6F2C207369676E61747572652074657374"
        },
        {
          "tag": "SignatureData",
          "type": "ByteString",
          "value": "3A4B5C6D7E8F901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12"
        },
        {
          "tag": "InitIndicator",
          "type": "Boolean",
          "value": true
        },
        {
          "tag": "FinalIndicator",
          "type": "Boolean",
          "value": true
        }
      ]
    }
    ```

=== "SignatureVerify Response"

    ```json
    {
      "tag": "SignatureVerifyResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "9382bfec-bd6c-46ed-8f00-90b467f77a15_pk"
        },
        {
          "tag": "ValidityIndicator",
          "type": "Enumeration",
          "value": "Valid"
        }
      ]
    }
    ```

#### Usage via HTTP API

To use Sign and SignatureVerify operations, send HTTP POST requests to the `/kmip/2_1` endpoint:

    ```bash
        # Sign operation example
        curl -X POST -H "Content-Type: application/json" \
          -d '{
            "tag": "RequestMessage",
            "value": [
              {
                "tag": "RequestHeader",
                "value": [
                  {
                    "tag": "ProtocolVersion",
                    "value": [
                      {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
                      {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}
                    ]
                  },
                  {"tag": "BatchCount", "type": "Integer", "value": 1}
                ]
              },
              {
                "tag": "BatchItem",
                "value": [
                  {"tag": "Operation", "type": "Enumeration", "value": "Sign"},
                  {
                    "tag": "RequestPayload",
                    "value": [
                      {"tag": "UniqueIdentifier", "type": "TextString", "value": "your-key-id"},
                      {"tag": "Data", "type": "ByteString", "value": "48656C6C6F"}
                    ]
                  }
                ]
              }
            ]
          }' \
          http://localhost:9998/kmip/2_1
    ```

#### Streaming Support

Both Sign and SignatureVerify operations support streaming for large data:

- Set `InitIndicator: true` to start streaming
- Use `CorrelationValue` to continue streaming sessions
- Set `FinalIndicator: true` to complete the operation
