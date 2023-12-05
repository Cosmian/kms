#### Specification

This operation requests the server to perform a decryption operation on the provided data using a Managed Cryptographic
Object as the key for the decryption operation.

The request contains information about the cryptographic parameters (mode and padding method), the data to be decrypted,
and the IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted from the request as they can be specified
as associated attributes of the Managed Cryptographic Object. The initialization vector/counter/nonce MAY also be
omitted from the request if the algorithm does not use an IV/Counter/Nonce.

The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and the result of the
decryption operation.

The success or failure of the operation is indicated by the Result Status (and if failure, the Result Reason) in the
response header.

#### Implementation

To see the list of supported cryptographic algorithms, please refer to [Supported Algorithms](./_algorithms.md).

#### Example - AES GCM decryption

Decrypting the text `Hello, world!` with symmetric key `027cced1-ff2b-4bd3-a200-db1041583bd` (go to [Create](.
/_create.md) to see how to create the symmetric key).

Instead of using the UID of the key, we can use the uniaue tag of the key `MySymmetricKey`. The key must be uniquely 
identified. It is possible to use multiple tags to identify a key; for instance symmetric keys automatically get a 
*system* tag `_kk`.

The request the same information as in the [`Encrypt` Response](./_encrypt.md):

 - the encrypted data 
 - the nounce: 12 bytes
 - the authentication tag: 16 bytes

=== "Request"
    ```json
    {
      "tag": "Decrypt",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "[\"MySymmetricKey\"]"
        },
        {
          "tag": "Data",
          "type": "ByteString",
          "value": "40D59A0735811135749A507FDEB3"
        },
        {
          "tag": "IvCounterNonce",
          "type": "ByteString",
          "value": "DBDD622A64F7D65E75894B1B"
        },
        {
          "tag": "AuthenticatedEncryptionTag",
          "type": "ByteString",
          "value": "50FCE680540BD3E96EFA9218A2F1009D"
        }
      ]
    }  
    ```

=== "Response"
    ```json
    {
      "tag": "DecryptResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "027cced1-ff2b-4bd3-a200-db1041583bdc"
        },
        {
          "tag": "Data",
          "type": "ByteString",
          // Hello, world! as UTF-8 bytes in hex
          "value": "48656C6C6F2C20776F726C64210A"
        }
      ]
    }   
    ```