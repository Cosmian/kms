[Chapter 8](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115738) of the KMIP 2.1
specification defines the Messages functionality, which enables sending/receiving multiple requests/responses at
once (also known as bulk mode).
This is the standard way to communicate with the KMIP server using the Binary protocol on port 5696 or the JSON protocol
on port 9998 and endpoint `/kmip`.

The `/kmip/2_1` endpoint is a Cosmian extension allowing the posting of Operations directly to the server without
the need for a `RequestMessage` wrapper.
This is particularly useful for operations like `Encrypt` and `Decrypt`.

Multiple operations can be included in a single `RequestMessage` query.
The server processes these operations sequentially, though they appear to execute simultaneously.
Each batch item contains an independent request.

For every request message sent, the server returns a response message containing the result status of the requested
operation,
along with any relevant result data or error messages.

### Request and response example

Below are canonical KMIP 2.1 message examples, following the mandatory XML schema AKLC-M-1-21.xml. Each request and response is shown in JSON TTLV format.

#### 1. CreateKeyPair

=== "Message Request"

    ```json
    {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "RequestHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "ClientCorrelationValue", "type": "TextString", "value": "AKLC-M-1-21 step=0" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "CreateKeyPair" },
                    { "tag": "RequestPayload", "type": "Structure", "value": [
                        { "tag": "CommonAttributes", "type": "Structure", "value": [
                            { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "RSA" },
                            { "tag": "CryptographicLength", "type": "Integer", "value": 2048 }
                        ] },
                        { "tag": "PrivateKeyAttributes", "type": "Structure", "value": [
                            { "tag": "Name", "type": "Structure", "value": [
                                { "tag": "NameValue", "type": "TextString", "value": "AKLC-M-1-21-private" },
                                { "tag": "NameType", "type": "Enumeration", "value": "UninterpretedTextString" }
                            ] },
                            { "tag": "CryptographicUsageMask", "type": "Integer", "value": "Sign" }
                        ] },
                        { "tag": "PublicKeyAttributes", "type": "Structure", "value": [
                            { "tag": "Name", "type": "Structure", "value": [
                                { "tag": "NameValue", "type": "TextString", "value": "AKLC-M-1-21-public" },
                                { "tag": "NameType", "type": "Enumeration", "value": "UninterpretedTextString" }
                            ] },
                            { "tag": "CryptographicUsageMask", "type": "Integer", "value": "Verify" }
                        ] }
                    ] }
                ]
            }
        ]
    }
    ```

=== "Message Response"

    ```json
    {
        "tag": "ResponseMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "ResponseHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "TimeStamp", "type": "DateTime", "value": "$NOW" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "CreateKeyPair" },
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
                    { "tag": "ResponsePayload", "type": "Structure", "value": [
                        { "tag": "PrivateKeyUniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" },
                        { "tag": "PublicKeyUniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_1" }
                    ] }
                ]
            }
        ]
    }
    ```

#### 2. GetAttributes (Private Key)

=== "Message Request"

    ```json
    {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "RequestHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "ClientCorrelationValue", "type": "TextString", "value": "AKLC-M-1-21 step=1" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "GetAttributes" },
                    { "tag": "RequestPayload", "type": "Structure", "value": [
                        { "tag": "UniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "State" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "CryptographicUsageMask" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "UniqueIdentifier" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "ObjectType" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "CryptographicAlgorithm" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "CryptographicLength" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "Digest" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "InitialDate" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "LastChangeDate" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "ActivationDate" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "OriginalCreationDate" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "RandomNumberGenerator" },
                        { "tag": "AttributeReference", "type": "Enumeration", "value": "KeyFormatType" }
                    ] }
                ]
            }
        ]
    }
    ```

=== "Message Response"

    ```json
    {
        "tag": "ResponseMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "ResponseHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "TimeStamp", "type": "DateTime", "value": "$NOW" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "GetAttributes" },
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
                    { "tag": "ResponsePayload", "type": "Structure", "value": [
                        { "tag": "UniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" },
                        { "tag": "Attributes", "type": "Structure", "value": [
                            { "tag": "State", "type": "Enumeration", "value": "PreActive" },
                            { "tag": "CryptographicUsageMask", "type": "Integer", "value": "Sign" },
                            { "tag": "UniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" },
                            { "tag": "ObjectType", "type": "Enumeration", "value": "PrivateKey" },
                            { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "RSA" },
                            { "tag": "CryptographicLength", "type": "Integer", "value": 2048 },
                            { "tag": "Digest", "type": "Structure", "value": [
                                { "tag": "HashingAlgorithm", "type": "Enumeration", "value": "SHA_256" },
                                { "tag": "DigestValue", "type": "ByteString", "value": "8eb422ae2b006a05d3c8a542a28536735241b6dc1c37926bc8007bd6220d9230" },
                                { "tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS_1" }
                            ] },
                            { "tag": "InitialDate", "type": "DateTime", "value": "$NOW" },
                            { "tag": "LastChangeDate", "type": "DateTime", "value": "$NOW" },
                            { "tag": "OriginalCreationDate", "type": "DateTime", "value": "$NOW" },
                            { "tag": "RandomNumberGenerator", "type": "Structure", "value": [
                                { "tag": "RNGAlgorithm", "type": "Enumeration", "value": "ANSIX9_31" },
                                { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES" },
                                { "tag": "CryptographicLength", "type": "Integer", "value": 256 }
                            ] },
                            { "tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS_1" }
                        ] }
                    ] }
                ]
            }
        ]
    }
    ```

#### 3. Destroy (Private Key)

=== "Message Request"

    ```json
    {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "RequestHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "ClientCorrelationValue", "type": "TextString", "value": "AKLC-M-1-21 step=3" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "Destroy" },
                    { "tag": "RequestPayload", "type": "Structure", "value": [
                        { "tag": "UniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" }
                    ] }
                ]
            }
        ]
    }
    ```

=== "Message Response"

    ```json
    {
        "tag": "ResponseMessage",
        "type": "Structure",
        "value": [
            {
                "tag": "ResponseHeader",
                "type": "Structure",
                "value": [
                    { "tag": "ProtocolVersion", "type": "Structure", "value": [
                        { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                        { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                    ] },
                    { "tag": "TimeStamp", "type": "DateTime", "value": "$NOW" },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": "Destroy" },
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
                    { "tag": "ResponsePayload", "type": "Structure", "value": [
                        { "tag": "UniqueIdentifier", "type": "TextString", "value": "$UNIQUE_IDENTIFIER_0" }
                    ] }
                ]
            }
        ]
    }
    ```
