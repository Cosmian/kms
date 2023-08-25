from asyncio import Future
from typing import List, Optional, Tuple, Union

from cloudproof_cover_crypt import (
    Attribute,
    MasterSecretKey,
    Policy,
    MasterPublicKey,
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

    def __init__(
        self,
        server_url: str,
        api_key: Optional[str] = "",
        database_secret: Optional[str] = "",
        insecure_mode: bool = False,
    ) -> None:
        """Instantiate a KMS Client

        Args:
            server_url (str): url of the KMS server
            api_key (str, optional): to authenticate to the KMS server
            database_secret (str, optional): to authenticate to the KMS database
            insecure_mode (bool, optional): accept self signed ssl cert. Defaults to False.
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
        self,
        attributes: List[Union[Attribute, str]],
        master_secret_key_identifier: Optional[str],
        tags: Optional[List[str]] = None,
    ) -> Future[Tuple[str, str]]:
        """Rotate the given policy attributes. This will rekey in the KMS:
            - the Master Keys
            - all User Decryption Keys that contain one of these attributes in their policy and are not rotated.

        Args:
            attributes (List[Union[Attribute, str]]): attributes to rotate e.g. ["Department::HR"]
            master_secret_key_identifier (Optional[str]): master secret key UID. Tags should be supplied if the ID is not given.
            tags: (Optional[List[str][]) tags to retrieve the master secret key if it the id is not satisfied

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
            access_policy_str (str): user access policy
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
        public_key_identifier: Optional[str],
        tags: Optional[List[str]] = None,
        header_metadata: Optional[bytes] = None,
        authentication_data: Optional[bytes] = None,
    ) -> Future[bytes]:
        """Hybrid encryption. Concatenates the encrypted header and the symmetric
        ciphertext.

        Args:
            encryption_policy_str (str): the access policy to use for encryption
            data (bytes): data to encrypt
            public_key_identifier (str): identifier of the public key. If not specified, tags must be provided.
            tags (Optional[List[str]]): tags to use to find the public key
            header_metadata (Optional[bytes]): additional data to symmetrically encrypt in the header
            authentication_data (Optional[bytes]): authentication data to use in symmetric encryptions

        Returns:
            Future[bytes]: ciphertext
        """
    def cover_crypt_decryption(
        self,
        encrypted_data: bytes,
        user_key_identifier: Optional[str],
        tags: Optional[List[str]] = None,
        authentication_data: Optional[bytes] = None,
    ) -> Future[Tuple[bytes, bytes]]:
        """Hybrid decryption.

        Args:
            encrypted_data (bytes): encrypted header || symmetric ciphertext
            user_key_identifier (str): identifier of the user key. If not specified, tags must be provided.
            tags (Optional[List[str]]): tags to use to find the user key
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
        self,
        revocation_reason: str,
        key_identifier: Optional[str],
        tags: Optional[List[str]] = None,
    ) -> Future[str]:
        """Mark a CoverCrypt Key as revoked

        Args:
            revocation_reason (str): explanation of the revocation
            key_identifier (str): identifier of the user key. If not specified, tags must be provided.
            tags (Optional[List[str]]): tags to use to find the user key

        Returns:
            Future[str]: uid of the revoked key
        """
    def destroy_cover_crypt_key(
        self,
        key_identifier: Optional[str],
        tags: Optional[List[str]] = None,
    ) -> Future[str]:
        """Mark a CoverCrypt Key as destroyed

        Args:
            key_identifier (str): identifier of the user key. If not specified, tags must be provided.
            tags (Optional[List[str]]): tags to use to find the user key

        Returns:
            Future[str]: uid of the destroyed key
        """
