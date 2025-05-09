[Chapter 8](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115738) of the KMIP 2.1
specification defines the Messages functionality, which enables sending/receiving multiple requests/responses at
once (also known as bulk mode).
This is the standard way to communicate with the KMIP server using the Binary protocol on port 4696 or the JSON protocol
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

A single `RequestMessage`, with one `CreateKeyPair` operation and one `Locate` operation.

=== "Message Request"

    ```json
    {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [ {
            "tag": "Header",
            "type": "Structure",
            "value": [ {
                "tag": "ProtocolVersion",
                "type": "Structure",
                "value": [ {
                        "tag": "ProtocolVersionMajor",
                        "type": "Integer",
                        "value": 2,
                    }, {
                        "tag": "ProtocolVersionMinor",
                        "type": "Integer",
                        "value": 1,
                    },
                ]
            }, {
                "tag": "MaximumResponseSize",
                "type": "Integer",
                "value": 9999,
            }, {
                "tag": "BatchCount",
                "type": "Integer",
                "value": 2,
            } ]
        }, {
            "tag": "BatchItem",
            "type": "Structure",
            "value": [ {
                "tag": "Items",
                "type": "Structure",
                "value": [ {
                    "tag": "Operation",
                    "type": "Enumeration",
                    "value": "CreateKeyPair",
                }, {
                    "tag": "RequestPayload",
                    "type": "Structure",
                    "value": [ {
                        "tag": "CommonAttributes",
                        "type": "Structure",
                        "value": [ {
                            "tag": "CryptographicAlgorithm",
                            "type": "Enumeration",
                            "value": "ECDH",
                        }, {
                            "tag": "CryptographicLength",
                            "type": "Integer",
                            "value": 256,
                        }, {
                            "tag": "CryptographicDomainParameters",
                            "type": "Structure",
                            "value": [ {
                                    "tag": "QLength",
                                    "type": "Integer",
                                    "value": 256,
                                }, {
                                    "tag": "RecommendedCurve",
                                    "type": "Enumeration",
                                    "value": "CURVE25519",
                                },
                            ],
                        }, {
                            "tag": "CryptographicUsageMask",
                            "type": "Integer",
                            "value": 2108,
                        }, {
                            "tag": "KeyFormatType",
                            "type": "Enumeration",
                            "value": "ECPrivateKey",
                        }, {
                            "tag": "ObjectType",
                            "type": "Enumeration",
                            "value": "PrivateKey",
                        } ],
                    } ],
                } ],
            }, {
                "tag": "BatchItem",
                "type": "Structure",
                "value": [ {
                    "tag": "Operation",
                    "type": "Enumeration",
                    "value": "Locate"
                }, {
                    "tag": "RequestPayload",
                    "type": "Structure",
                    "value": [ {
                        "tag": "Attributes",
                        "type": "Structure",
                        "value": [],
                    } ],
                },
            } ],
        } ],
    }
    ```

=== "Message Response"

    ```json
    {
        "tag": "ResponseMessage",
        "type": "Structure",
        "value": [ {
            "tag": "Header",
            "type": "Structure",
            "value": [ {
                "tag": "ProtocolVersion",
                "type": "Structure",
                "value": [ {
                    "tag": "ProtocolVersionMajor",
                    "type": "Integer",
                    "value": 2,
                }, {
                    "tag": "ProtocolVersionMinor",
                    "type": "Integer",
                    "value": 1,
                } ]
            }, {
                "tag": "Timestamp",
                "type": "LongInteger",
                "value": 1698748303,
            }, {
                "tag": "BatchCount",
                "type": "Integer",
                "value": 2,
            } ]
        }, {
            "tag": "BatchItem",
            "type": "Structure",
            "value": [ {
                "tag": "Items",
                "type": "Structure",
                "value": [ {
                    "tag": "Operation",
                    "type": "Enumeration",
                    "value": "CreateKeyPair",
                }, {
                    "tag": "ResultStatus",
                    "type": "Enumeration",
                    "value": "Success",
                }, {
                    "tag": "ResponsePayload",
                    "type": "Structure",
                    "value": [ {
                        "tag": "PrivateKeyUniqueIdentifier",
                        "type": "TextString",
                        "value": "7c293777-794f-41fa-95f2-4f0a3bc730b8",
                    }, {
                        "tag": "PublicKeyUniqueIdentifier",
                        "type": "TextString",
                        "value": "042c8439-16f8-406f-b425-c18a69fb56a7",
                    } ],
                } ],
            }, {
                "tag": "BtachItem",
                "type": "Structure",
                "value": [ {
                    "tag": "Operation",
                    "type": "Enumeration",
                    "value": "Locate"
                }, {
                    "tag": "ResponsePayload",
                    "type": "Structure",
                    "value": [ {
                        "tag": "LocatedItems",
                        "type": "Integer",
                        "value": 2,
                    }, {
                        "tag": "UniqueIdentifier",
                        "type": "Structure",
                        "value": [ {
                            "tag": "PrivateKeyUniqueIdentifier",
                            "type": "TextString",
                            "value": "7c293777-794f-41fa-95f2-4f0a3bc730b8",
                        }, {
                            "tag": "PublicKeyUniqueIdentifier",
                            "type": "TextString",
                            "value": "042c8439-16f8-406f-b425-c18a69fb56a7",
                        } ],
                    } ],
                } ],
            } ],
        } ],
    }
    ```
