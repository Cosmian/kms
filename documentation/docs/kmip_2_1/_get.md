#### specification

This operation requests that the server returns the Managed Object specified by its Unique Identifier. Only a single object is returned.

The response contains the Unique Identifier of the object, along with the object itself, which MAY be wrapped using a wrapping key as specified in the request. The following key format capabilities SHALL be assumed by the client; restrictions apply when the client requests the server to return an object in a particular
format:

- If a client registers a key in a given format, the server SHALL be able to return the key during the Get operation in the same format that was used when the key was registered.

- Any other format conversion MAY be supported by the server.

If Key Format Type is specified to be PKCS#12 then the response payload shall be a PKCS#12 container as specified by [RFC7292].

The Unique Identifier shall be either that of a private key or certificate to be included in the response.

The container shall be protected using the Secret Data object specified via the private key or certificate's PKCS#12 Password Link. The current certificate chain shall also be included as determined by using the private key's Public Key link to get the corresponding public key (where relevant) and then using that public key's PKCS#12 Certificate Link to get the base certificate, and then using each certificate's Certificate Link to build the certificate chain.  It is an error if there is more than one valid certificate chain.

#### implementation

The Cosmian KMS server returns the retrieved object in the same format as it was inserted and does not perform the conversion.

=== "Java"

    ``` java
    String privateMasterKeyUniqueIdentifier = ...;
    PublicKey masterPublicKey = abe.retrievePrivateMasterKey(privateMasterKeyUniqueIdentifier);

    String publicMasterKeyUniqueIdentifier = ...;
    PrivateKey masterPrivateKey = abe.retrievePublicMasterKey(publicMasterKeyUniqueIdentifier);

    String userDecryptionKeyUniqueIdentifier = ...;
    PrivateKey userKey = abe.retrieveUserDecryptionKey(userDecryptionKeyUniqueIdentifier);
    ```