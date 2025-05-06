In [chapter 8](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115738), the KMIP 2.1
specification defines Messages functionality, which is the proper way to send/receive multiple requests/responses at
once in KMIP (also called bulk mode).

One can insert multiple requests in a single Message query.
These requests are processed sequentially and simultaneously by the server.
The requests wrapped into the batch items are totally independent.

For each message request sent, a message response is returned, yielding a result status of the requested operation, and
potentially associated result data or error messages.

### Request and response example

Two operation requests and their responses are packed into a single Message, with one `CreateKeyPair` operation and
one `Locate` operation.

=== "Message Request"

    ```json
    {
        "tag": "Message",
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
            "tag": "Items",
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
                "tag": "Items",
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
        "tag": "Message",
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
            "tag": "Items",
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
                "tag": "Items",
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
