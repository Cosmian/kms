from asyncio import Future
from typing import List, Optional, Tuple, Union

from cloudproof_cover_crypt import Attribute, Policy

UidOrTags = Union[str, List[str]]
"""KMS Objects (e.g. keys) can either be referenced by an UID using a single string, or by a list of tags using a list of string."""

class KmsObject:
    def object_type(self) -> str:
        """Get the type of the underlying KMIP object.

        Returns:
            str
        """

    def key_block(self) -> bytes:
        """Retrieve key bytes

        Returns:
            bytes
        """

class KmsEncryptResponse:
    """Represents the response from a KMS encryption operation."""

    @staticmethod
    def from_json(data: str) -> KmsEncryptResponse:
        """
        Creates an instance from a JSON string.

        Args:
            data (str): The JSON string representing the KmsEncryptResponse.
        """

    def unique_identifier(self) -> str:
        """
        Retrieves the unique identifier of the key used during encryption.

        Returns:
            str: The unique identifier of the key.
        """

    def data(self) -> bytes:
        """
        Retrieves the data bytes from the encryption response.

        Returns:
            bytes.
        """

    def iv_counter_nonce(self) -> bytes:
        """
        Retrieves the IV, Counter, or Nonce bytes from the encryption response.

        Returns:
            bytes
        """

    def authenticated_encryption_tag(self) -> bytes:
        """
        Retrieves the authentication tag bytes from the encryption response.

        Returns:
            bytes
        """

    def correlation_value(self) -> bytes:
        """
        Retrieves the correlation value bytes from the encryption response.

        Returns:
            bytes
        """

class KmsClient:
    """Python client for a Key Management System (KMS). The methods return Future object which
    can be used to track and manage the status of the requests asynchronously.
    """

    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = None,
        client_pkcs12_path: Optional[str] = None,
        client_pkcs12_password: Optional[str] = None,
        database_secret: Optional[str] = None,
        insecure_mode: bool = False,
        allowed_tee_tls_cert: Optional[bytes] = None,
    ) -> None:
        """Instantiate a KMS Client

        Args:
            server_url (str): url of the KMS server
            api_key (str, optional): to authenticate to the KMS server
            client_pkcs12_path (Optional[str]): optional path to client PKCS12, to authenticate to the KMS
            client_pkcs12_password (Optional[str]): optional password to client PKCS12
            database_secret (str, optional): to authenticate to the KMS database
            insecure_mode (bool, optional): accept self signed ssl cert. Defaults to False.
            allowed_tee_tls_cert (Optional[bytes])  : PEM certificate of a tee.
        """

    def create_cover_crypt_master_key_pair(
        self, policy: Union[Policy, bytes]
    ) -> Future[Tuple[str, str]]:
        """Generate the master authority keys for supplied Policy.

        Args:
            policy (Union[Policy, str]): policy used to generate the keys

        Returns:
            Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
        """

    def import_cover_crypt_master_private_key(
        self,
        private_key: bytes,
        replace_existing: bool,
        link_master_public_key_id: str,
        policy: bytes,
        tags: Optional[List[str]],
        is_wrapped: bool,
        wrapping_password: Optional[str] = None,
        unique_identifier: Optional[str] = None,
    ) -> Future[str]:
        """Import a Private Master Key into the KMS.

        Args:
            private_key (bytes): key bytes
            replace_existing (bool): set to true to replace an existing key with the same identifier
            link_master_public_key_id (str): id of the matching master public key
            policy (bytes): policy related to the key
            is_wrapped (bool): whether the key is wrapped
            wrapping_password (Optional[str]): password used to wrap the key
            unique_identifier (Optional[str]): the unique identifier of the key

        Returns:
            Future[str]: the unique identifier of the key
        """

    def import_cover_crypt_public_key(
        self,
        public_key: bytes,
        replace_existing: bool,
        policy: bytes,
        link_master_private_key_id: str,
        unique_identifier: Optional[str] = None,
    ) -> Future[str]:
        """Import a Public Master Key into the KMS.

        Args:
            public_key (bytes): key bytes
            replace_existing (bool): set to true to replace an existing key with the same identifier
            policy (bytes): policy related to the key
            link_master_private_key_id (str): id of the matching master private key
            unique_identifier (Optional[str]): the unique identifier of the key

        Returns:
            Future[str]: the unique identifier of the key
        """

    def rekey_cover_crypt_access_policy(
        self,
        access_policy: str,
        master_secret_key_identifier: UidOrTags,
    ) -> Future[Tuple[str, str]]:
        """Generate new keys associated to the given access policy in the master keys.
        This will automatically refresh the corresponding user keys.

        Args:
            - `access_policy` (str): describe the keys to renew
            - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
        """

    async def prune_cover_crypt_access_policy(
        self,
        access_policy: str,
        master_secret_key_identifier: UidOrTags,
    ) -> Tuple[str, str]:
        """
        Removes old keys associated to the access policy from the master keys.
        This will automatically refresh the corresponding user keys.
        This will permanently remove access to old ciphertexts.

        Args:
            - `access_policy` (str): describe the keys to renew
            - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """

    async def remove_cover_crypt_attribute(
        self,
        attribute: str,
        master_secret_key_identifier: UidOrTags,
    ) -> Tuple[str, str]:
        """
        Remove a specific attribute from a keypair's policy.
        Permanently removes the ability to use this attribute in both encryptions and decryptions.

        Note that messages whose encryption policy does not contain any other attributes
        belonging to the dimension of the deleted attribute will be lost.

        This will rekey in the KMS:
        - the master keys
        - all user decryption keys that contain one of these attributes in their policy.

        Args:
            attributes (Union[Attribute, str]): Attributes to remove e.g. "Department::HR"
            master_secret_key_identifier (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """

    async def disable_cover_crypt_attribute(
        self,
        attribute: str,
        master_secret_key_identifier: UidOrTags,
    ) -> Tuple[str, str]:
        """
        Disable a specific attribute from a keypair's policy.
        Prevents the encryption of new messages for this attribute while keeping the ability to decrypt existing ciphertexts.

        This will rekey in the KMS:
        - the master keys

        Args:
            attributes (Union[Attribute, str]): Attributes to disable e.g. "Department::HR"
            master_secret_key_identifier (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """

    async def add_cover_crypt_attribute(
        self,
        attribute: str,
        is_hybridized: bool,
        master_secret_key_identifier: UidOrTags,
    ) -> Tuple[str, str]:
        """
        Add a specific attribute to a keypair's policy.

        This will rekey in the KMS:
        - the master keys

        Args:
            attributes (Union[Attribute, str]): Attributes to disable e.g. "Department::HR"
            is_hybridized (bool): hint for encryption
            master_secret_key_identifier (Union[str, List[str])): master secret key referenced by its UID or a list of tags


        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """

    async def rename_cover_crypt_attribute(
        self,
        attribute: str,
        new_name: str,
        master_secret_key_identifier: UidOrTags,
    ) -> Tuple[str, str]:
        """
        Add a specific attribute to a keypair's policy.

        Args:
            attributes (Union[Attribute, str]): Attributes to disable e.g. "Department::HR"
            new_name (str): the new name for the attribute
            master_secret_key_identifier (Union[str, List[str])): master secret key referenced by its UID or a list of tags

        Returns:
            Tuple[str, str]: (Public key UID, Master secret key UID)
        """

    def create_cover_crypt_user_decryption_key(
        self,
        access_policy: str,
        master_secret_key_identifier: str,
        tags: Optional[str] = None,
    ) -> Future[str]:
        """Generate a user secret key.
        A new user secret key does NOT include to old (i.e. rotated) partitions.

        Args:
            access_policy(str): user access policy
            master_secret_key_identifier (str): master secret key UID
            tags (Optional[List[str]]): optional tags to use with the keys

        Returns:
            Future[str]: User secret key UID
        """

    def import_cover_crypt_user_decryption_key(
        self,
        private_key: bytes,
        replace_existing: bool,
        link_master_private_key_id: str,
        access_policy: str,
        tags: Optional[List[str]] = None,
        is_wrapped: Optional[bool] = None,
        wrapping_password: Optional[str] = None,
        unique_identifier: Optional[str] = None,
    ) -> Future[str]:
        """Import a user secret key into the KMS.

        Args:
            private_key (bytes): key bytes
            replace_existing (bool): set to true to replace an existing key with the same identifier
            link_master_private_key_id (str): id of the matching master private key
            access_policy(str): user access policy
            tags (Optional[List[str]]): tags associated to the key
            is_wrapped (bool): whether the key is wrapped
            wrapping_password (Optional[str]): password used to wrap the key
            unique_identifier (Optional[str]): the unique identifier of the key

        Returns:
            Future[str]: User secret key UID
        """

    def cover_crypt_encryption(
        self,
        encryption_policy_str: str,
        data: bytes,
        public_key_identifier: UidOrTags,
        header_metadata: Optional[bytes] = None,
        authentication_data: Optional[bytes] = None,
    ) -> Future[bytes]:
        """Hybrid encryption. Concatenates the encrypted header and the symmetric
        ciphertext.

        Args:
            encryption_policy_str (str): the access policy to use for encryption
            data (bytes): data to encrypt
            public_key_identifier (Union[str, List[str]]): public key unique id or associated tags
            header_metadata (Optional[bytes]): additional data to symmetrically encrypt in the header
            authentication_data (Optional[bytes]): authentication data to use in symmetric encryptions

        Returns:
            Future[bytes]: ciphertext
        """

    def cover_crypt_decryption(
        self,
        encrypted_data: bytes,
        user_key_identifier: UidOrTags,
        authentication_data: Optional[bytes] = None,
    ) -> Future[Tuple[bytes, bytes]]:
        """Hybrid decryption.

        Args:
            encrypted_data (bytes): encrypted header || symmetric ciphertext
            user_key_identifier (Union[str, List[str]]): user secret key unique id or associated tags
            authentication_data (Optional[bytes]): authentication data to use in symmetric decryption

        Returns:
            Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata bytes)
        """

    def get_object(self, unique_identifier: UidOrTags) -> Future[KmsObject]:
        """Fetch KMIP object by UID.

        Args:
            unique_identifier (Union[str, List[str]]): object unique id or associated tags

        Returns:
            Future[KmsObject]
        """

    def revoke_key(
        self,
        revocation_reason: str,
        key_identifier: UidOrTags,
    ) -> Future[str]:
        """Mark a CoverCrypt Key as revoked

        Args:
            revocation_reason (str): explanation of the revocation
            key_identifier (Union[str, List[str]]): key unique id or associated tags

        Returns:
            Future[str]: uid of the revoked key
        """

    def destroy_key(
        self,
        key_identifier: UidOrTags,
    ) -> Future[str]:
        """Mark a CoverCrypt Key as destroyed

        Args:
            key_identifier (Union[str, List[str]]): key unique id or associated tags

        Returns:
            Future[str]: uid of the destroyed key
        """

    def create_symmetric_key(
        self,
        key_len_in_bits: int,
        algorithm: str = "AES",
        tags: Optional[List[str]] = None,
    ) -> Future[str]:
        """Create a symmetric key using the specified key length, cryptographic algorithm, and optional tags

        Args:
            key_len_in_bits (int): length of the key in bits
            algorithm (str, optional): cryptographic algorithm to be used, supported values are "AES" and "ChaCha20". Defaults to "AES"
            tags (List[str], optional): tags associated with the key

        Returns:
            Future[str]: uid of the created key.
        """

    def encrypt(
        self,
        data: bytes,
        key_identifier: UidOrTags,
    ) -> Future[KmsEncryptResponse]:
        """Encrypts the provided binary data using the specified key identifier or tags

        Args:
            data (bytes): binary data to be encrypted
            key_identifier (Union[str, List[str]]): secret key unique id or associated tags

        Returns:
            Future[KmsEncryptResponse]: encryption result
        """

    def decrypt(
        self,
        encrypted_data: bytes,
        key_identifier: UidOrTags,
        iv_counter_nonce: Optional[bytes] = None,
        authentication_encryption_tag: Optional[bytes] = None,
    ) -> Future[bytes]:
        """Hybrid decryption.

        Args:
            encrypted_data (bytes): ciphertext
            key_identifier (Union[str, List[str]]): secret key unique id or associated tags
            iv_counter_nonce (Optional[bytes]): the initialization vector, counter or nonce to be used
            authentication_encryption_tag (Optional[bytes]): additional binary data used for authentication

        Returns:
            Future[bytes]: plaintext bytes
        """
