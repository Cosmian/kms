# -*- coding: utf-8 -*-
import unittest

from cloudproof_cover_crypt import (
    MasterSecretKey,
    Policy,
    PolicyAxis,
    PublicKey,
    UserSecretKey,
)
from cosmian_kms import KmsClient


class TestKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient("http://localhost:9998")

        # Create Policy
        self.policy = Policy()
        self.policy.add_axis(
            PolicyAxis(
                "Security Level",
                [
                    ("Protected", False),
                    ("Confidential", False),
                    ("Top Secret", False),
                ],
                hierarchical=True,
            )
        )
        self.policy.add_axis(
            PolicyAxis(
                "Department",
                [("FIN", False), ("MKG", False), ("HR", False)],
                hierarchical=False,
            )
        )

        # Generate master key pair
        (
            self.pubkey_uid,
            self.privkey_uid,
        ) = await self.client.create_cover_crypt_master_key_pair(self.policy.to_bytes())

    async def test_master_keys(self) -> None:
        # Query public key from KMS
        pubkey = await self.client.get_object(self.pubkey_uid)
        self.assertEqual(pubkey.object_type(), "PublicKey")
        self.assertIsInstance(PublicKey.from_bytes(pubkey.key_block()), PublicKey)

        # Query private key from KMS
        privkey = await self.client.get_object(self.privkey_uid)
        self.assertEqual(privkey.object_type(), "PrivateKey")
        self.assertIsInstance(
            MasterSecretKey.from_bytes(privkey.key_block()), MasterSecretKey
        )

        # Import custom private key
        custom_privkey_uid = (
            await self.client.import_cover_crypt_master_private_key_request(
                privkey.key_block(),
                True,
                self.pubkey_uid,
                self.policy.to_bytes(),
                [],
                False,
                None,
                "my_custom_privkey",
            )
        )
        self.assertEqual(custom_privkey_uid, "my_custom_privkey")

        # Import custom public key
        custom_pubkey_uid = await self.client.import_cover_crypt_public_key_request(
            pubkey.key_block(),
            True,
            self.policy.to_bytes(),
            self.privkey_uid,
            "my_custom_pubkey",
        )
        self.assertEqual(custom_pubkey_uid, "my_custom_pubkey")

    async def test_user_key_generation(self) -> None:
        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::MKG && Security Level::Confidential", self.privkey_uid
        )

        # Query private key from KMS
        userkey = await self.client.get_object(userkey_uid)
        self.assertEqual(userkey.object_type(), "PrivateKey")
        self.assertIsInstance(
            UserSecretKey.from_bytes(userkey.key_block()), UserSecretKey
        )

        # Import custom user key
        custom_userkey_uid = (
            await self.client.import_cover_crypt_user_decryption_key_request(
                userkey.key_block(),
                True,
                self.privkey_uid,
                "Department::MKG && Security Level::Confidential",
                None,
                False,
                None,
                "my_custom_userkey",
            )
        )
        self.assertEqual(custom_userkey_uid, "my_custom_userkey")

        # Revoke key
        revoked_uid = await self.client.revoke_cover_crypt_key(
            "test", 
            userkey_uid
        )
        self.assertEqual(revoked_uid, userkey_uid)

        # Destroy key
        destroyed_uid = await self.client.destroy_cover_crypt_key(userkey_uid)
        self.assertEqual(destroyed_uid, userkey_uid)

    async def test_simple_encryption_decryption_without_metadata(self) -> None:
        # Encryption
        to_encrypt = b"My secret data"
        protected_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Protected",
            to_encrypt,
            self.pubkey_uid,
        )

        topsecret_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Top Secret",
            to_encrypt,
            self.pubkey_uid,
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::MKG && Security Level::Confidential", self.privkey_uid
        )

        # Successful decryption
        plaintext, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext,
            userkey_uid,
        )
        self.assertEqual(bytes(plaintext), to_encrypt)

        # Wrong permission
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                topsecret_mkg_ciphertext,
                userkey_uid,
            )

    async def test_simple_encryption_decryption_with_metadata(self) -> None:
        # Encryption
        to_encrypt = b"My secret data"
        protected_fin_ciphertext = await self.client.cover_crypt_encryption(
            "Department::FIN && Security Level::Protected",
            to_encrypt,
            self.pubkey_uid,
            header_metadata=b"header message",
            authentication_data=b"auth token",
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::FIN && Security Level::Protected", self.privkey_uid
        )

        # Successful decryption
        plaintext, header = await self.client.cover_crypt_decryption(
            protected_fin_ciphertext,
            userkey_uid,
            authentication_data=b"auth token",
        )
        self.assertEqual(bytes(plaintext), to_encrypt)
        self.assertEqual(bytes(header), b"header message")

        # Missing authentication data
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                protected_fin_ciphertext,
                userkey_uid,
            )

    async def test_policy_rotation_encryption_decryption(self) -> None:
        # Encryption
        old_message = b"My secret data part 1"
        old_ciphertext = await self.client.cover_crypt_encryption(
            "Department::HR && Security Level::Confidential",
            old_message,
            self.pubkey_uid,
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::HR && Security Level::Top Secret", self.privkey_uid
        )

        # Rekey
        (
            new_pubkey_uid,
            new_privkey_uid,
        ) = await self.client.rotate_cover_crypt_attributes(
            ["Department::HR"], self.privkey_uid,
        )
        self.assertEqual(self.pubkey_uid, new_pubkey_uid)
        self.assertEqual(self.privkey_uid, new_privkey_uid)

        new_message = b"My secret data part 2"
        new_ciphertext = await self.client.cover_crypt_encryption(
            "Department::HR && Security Level::Top Secret",
            new_message,
            self.pubkey_uid,
        )

        # Decrypt old message
        plaintext, _ = await self.client.cover_crypt_decryption(
            old_ciphertext,
            userkey_uid,
        )
        self.assertEqual(bytes(plaintext), old_message)

        # Decrypt new message
        plaintext, _ = await self.client.cover_crypt_decryption(
            new_ciphertext,
            userkey_uid,
        )
        self.assertEqual(bytes(plaintext), new_message)


if __name__ == "__main__":
    unittest.main()
