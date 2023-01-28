from typing import Optional, Tuple, Union, List
from asyncio import Future
from cosmian_cover_crypt import (
    Policy,
    Attribute,
    PublicKey,
    MasterSecretKey,
    UserSecretKey,
)

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

class KmsClient:
    """Python client for a Key Management System (KMS). The methods return Future object which
    can be used to track and manage the status of the requests asynchronously.
    """

    def __init__(self, server_url: str, api_key: Optional[str] = "") -> None:
        """Instantiate a KMS Client

        Args:
            server_url (str): url of the KMS server
            api_key (Optional[str]): to authenticate to the KMS server
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
    def import_cover_crypt_master_private_key_request(
        self,
        private_key: bytes,
        replace_existing: bool,
        link_master_public_key_id: str,
        policy: bytes,
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
    def import_cover_crypt_public_key_request(
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
    def rotate_cover_crypt_attributes(
        self, master_secret_key_identifier: str, attributes: List[Union[Attribute, str]]
    ) -> Future[Tuple[str, str]]:
        """Rotate the given policy attributes. This will rekey in the KMS:
            - the Master Keys
            - all User Decryption Keys that contain one of these attributes in their policy and are not rotated.

        Args:
            master_secret_key_identifier (str): master secret key UID
            attributes (List[Union[Attribute, str]]): attributes to rotate e.g. ["Department::HR"]

        Returns:
            Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
        """
    def create_cover_crypt_user_decryption_key(
        self, access_policy_str: str, master_secret_key_identifier: str
    ) -> Future[str]:
        """Generate a user secret key.
        A new user secret key does NOT include to old (i.e. rotated) partitions.

        Args:
            access_policy_str (str): user access policy
            master_secret_key_identifier (str): master secret key UID

        Returns:
            Future[str]: User secret key UID
        """
    def import_cover_crypt_user_decryption_key_request(
        self,
        private_key: bytes,
        replace_existing: bool,
        link_master_private_key_id: str,
        access_policy_str: str,
        is_wrapped: bool,
        wrapping_password: Optional[str] = None,
        unique_identifier: Optional[str] = None,
    ) -> Future[str]:
        """Import a user secret key into the KMS.

        Args:
            private_key (bytes): key bytes
            replace_existing (bool): set to true to replace an existing key with the same identifier
            link_master_private_key_id (str): id of the matching master private key
            access_policy_str (str): user access policy
            is_wrapped (bool): whether the key is wrapped
            wrapping_password (Optional[str]): password used to wrap the key
            unique_identifier (Optional[str]): the unique identifier of the key

        Returns:
            Future[str]: User secret key UID
        """
    def cover_crypt_encryption(
        self,
        public_key_identifier: str,
        encryption_policy_str: str,
        data: bytes,
        header_metadata: Optional[bytes] = None,
        authentication_data: Optional[bytes] = None,
    ) -> Future[bytes]:
        """Hybrid encryption. Concatenates the encrypted header and the symmetric
        ciphertext.

        Args:
            public_key_identifier (str): identifier of the public key
            encryption_policy_str (str): the access policy to use for encryption
            data (bytes): data to encrypt
            header_metadata (Optional[bytes]): additional data to symmetrically encrypt in the header
            authentication_data (Optional[bytes]): authentication data to use in symmetric encryptions

        Returns:
            Future[bytes]: ciphertext
        """
    def cover_crypt_decryption(
        self,
        user_key_identifier: str,
        encrypted_data: bytes,
        authentication_data: Optional[bytes] = None,
    ) -> Future[Tuple[bytes, bytes]]:
        """Hybrid decryption.

        Args:
            user_key_identifier (str): user secret key identifier
            encrypted_data (bytes): encrypted header || symmetric ciphertext
            authentication_data (Optional[bytes]): authentication data to use in symmetric decryption

        Returns:
            Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata bytes)
        """
    def get_object(self, unique_identifier: str) -> Future[KmsObject]:
        """Fetch KMIP object by UID.

        Args:
            unique_identifier (str): the object unique identifier in the KMS

        Returns:
            Future[KmsObject]
        """
    def revoke_cover_crypt_key(
        self, key_identifier: str, revocation_reason: str
    ) -> Future[str]:
        """Mark a CoverCrypt Key as revoked

        Args:
            key_identifier (str):  the key unique identifier in the KMS
            revocation_reason (str): explanation of the revocation

        Returns:
            Future[str]: uid of the revoked key
        """
    def destroy_cover_crypt_key(self, key_identifier: str) -> Future[str]:
        """Mark a CoverCrypt Key as destroyed

        Args:
            key_identifier (str):  the key unique identifier in the KMS

        Returns:
            Future[str]: uid of the destroyed key
        """
    def retrieve_cover_crypt_public_master_key(
        self, public_key_identifier: str
    ) -> Future[PublicKey]:
        """Fetch a CoverCrypt Public Master key.

        Args:
            public_key_identifier (str): the key unique identifier in the KMS

        Returns:
            Future[PublicKey]
        """
    def retrieve_cover_crypt_private_master_key(
        self, master_secret_key_identifier: str
    ) -> Future[MasterSecretKey]:
        """Fetch a CoverCrypt Private Master key.

        Args:
            master_secret_key_identifier (str): the key unique identifier in the KMS

        Returns:
            Future[MasterSecretKey]
        """
    def retrieve_cover_crypt_user_key(
        self, user_key_identifier: str
    ) -> Future[UserSecretKey]:
        """Fetch a CoverCrypt Private User key.

        Args:
            user_key_identifier (str): the key unique identifier in the KMS

        Returns:
            Future[UserSecretKey]
        """
