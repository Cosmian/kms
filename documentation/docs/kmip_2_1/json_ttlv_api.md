The easiest way to call the KMIP API is to use the `ckms` [command line interface](../cli/cli.md)
or one of the Cosmian [cloudproof libraries](https://github.com/Cosmian) which provide wrapper calls
in the corresponding language.

Without the use of a library, the client must build the JSON TTLV messages from
an [Operation](./operations.md)
as described in the KMIP 2.1 specification, and issue an HTTP POST call to the `/kmip/2_1` endpoint
of the server.

Multiple operations can be sent in a single call using the [`Messages` API](./messages.md) .

!!!info  "Building JSON TTLV messages"

    Building JSON TTLV messages is a complex task and the easiest way to get started is to use the `ckms` CLI in
    debug mode to print the corresponding request and response messages.

    The debug mode is activated by setting the`RUST_LOG` environment variable
    to `cosmian_kms_client::kms_rest_client=debug`.
    See the [Debug Mode Example](#debug-mode-example) below.

To send multiple requests in a single call, se the [`Messages` API](./messages.md) .

#### Sample JSON TTLV messages

Please refer to the various [operations pages](./operations.md) for sample JSON TTLV messages.

#### Debug Mode Example

This creates a (default AES 256) symmetric key which will be tagged with the string `myKey`.

```bash
RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
ckms sym keys create --tag myKey
```

The CLI will then show the JSON TTLV requests and response:

```
2023-12-02T08:44:37.916528Z DEBUG ThreadId(01) cosmian_kms_client::kms_rest_client: crate/client/src/kms_rest_client.rs:663: ==>
{
  "tag": "Create",
  "type": "Structure",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SymmetricKey"
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
                  "value": "5B226D794B6579225D"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
2023-12-02T08:44:37.921325Z DEBUG ThreadId(01) cosmian_kms_client::kms_rest_client: crate/client/src/kms_rest_client.rs:675: <==
{
  "tag": "CreateResponse",
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
      "value": "5dc81bb2-648f-485f-b804-c6ea45467056"
    }
  ]
}
```
