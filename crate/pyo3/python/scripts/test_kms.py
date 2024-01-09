# -*- coding: utf-8 -*-
import unittest

from cloudproof_cover_crypt import (
    MasterPublicKey,
    MasterSecretKey,
    Policy,
    PolicyAxis,
    UserSecretKey,
)
from cosmian_kms import KmsClient


class TestCoverCryptKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient("http://localhost:9998")

        # Create Policy
        self.policy = Policy()
        self.policy.add_axis(
            PolicyAxis(
                "Security Level",
                [
                    ("Protected", False),
                    ("Confidential", True),
                    ("Top Secret", True),
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
            self.pub_key_uid,
            self.priv_key_uid,
        ) = await self.client.create_cover_crypt_master_key_pair(self.policy.to_bytes())

    async def test_master_keys(self) -> None:
        # Query public key from KMS
        pub_key = await self.client.get_object(self.pub_key_uid)
        self.assertEqual(pub_key.object_type(), "PublicKey")
        self.assertIsInstance(
            MasterPublicKey.from_bytes(pub_key.key_block()), MasterPublicKey
        )

        # Query private key from KMS
        priv_key = await self.client.get_object(self.priv_key_uid)
        self.assertEqual(priv_key.object_type(), "PrivateKey")
        self.assertIsInstance(
            MasterSecretKey.from_bytes(priv_key.key_block()), MasterSecretKey
        )

        # Import custom private key
        custom_priv_key_uid = await self.client.import_cover_crypt_master_private_key(
            priv_key.key_block(),
            True,
            self.pub_key_uid,
            self.policy.to_bytes(),
            [],
            False,
            None,
            "my_custom_priv_key",
        )
        self.assertEqual(custom_priv_key_uid, "my_custom_priv_key")

        # Import custom public key
        custom_pub_key_uid = await self.client.import_cover_crypt_public_key(
            pub_key.key_block(),
            True,
            self.policy.to_bytes(),
            self.priv_key_uid,
            "my_custom_pub_key",
        )
        self.assertEqual(custom_pub_key_uid, "my_custom_pub_key")

    async def test_user_key_generation(self) -> None:
        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::MKG && Security Level::Confidential",
            self.priv_key_uid,
        )

        # Query private key from KMS
        user_key = await self.client.get_object(user_key_uid)
        self.assertEqual(user_key.object_type(), "PrivateKey")
        self.assertIsInstance(
            UserSecretKey.from_bytes(user_key.key_block()), UserSecretKey
        )

        # Import custom user key
        custom_user_key_uid = await self.client.import_cover_crypt_user_decryption_key(
            user_key.key_block(),
            True,
            self.priv_key_uid,
            "Department::MKG && Security Level::Confidential",
            None,
            False,
            None,
            "my_custom_user_key",
        )
        self.assertEqual(custom_user_key_uid, "my_custom_user_key")

        # Revoke key
        revoked_uid = await self.client.revoke_key("test", user_key_uid)
        self.assertEqual(revoked_uid, user_key_uid)

        # Destroy key
        destroyed_uid = await self.client.destroy_key(user_key_uid)
        self.assertEqual(destroyed_uid, user_key_uid)

    async def test_simple_encryption_decryption_without_metadata(self) -> None:
        # Encryption
        to_encrypt = b"My secret data"
        protected_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Protected",
            to_encrypt,
            self.pub_key_uid,
        )

        topsecret_mkg_ciphertext = await self.client.cover_crypt_encryption(
            "Department::MKG && Security Level::Top Secret",
            to_encrypt,
            self.pub_key_uid,
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::MKG && Security Level::Confidential",
            self.priv_key_uid,
        )

        # Successful decryption
        plaintext, _ = await self.client.cover_crypt_decryption(
            protected_mkg_ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), to_encrypt)

        # Wrong permission
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                topsecret_mkg_ciphertext,
                user_key_uid,
            )

    async def test_simple_encryption_decryption_with_metadata(self) -> None:
        # Encryption
        to_encrypt = b"My secret data"
        protected_fin_ciphertext = await self.client.cover_crypt_encryption(
            "Department::FIN && Security Level::Protected",
            to_encrypt,
            self.pub_key_uid,
            header_metadata=b"header message",
            authentication_data=b"auth token",
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::FIN && Security Level::Protected",
            self.priv_key_uid,
        )

        # Successful decryption
        plaintext, header = await self.client.cover_crypt_decryption(
            protected_fin_ciphertext,
            user_key_uid,
            authentication_data=b"auth token",
        )
        self.assertEqual(bytes(plaintext), to_encrypt)
        self.assertEqual(bytes(header), b"header message")

        # Missing authentication data
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                protected_fin_ciphertext,
                user_key_uid,
            )

    async def test_policy_rotation_encryption_decryption(self) -> None:
        # Encryption
        old_message = b"My secret data part 1"
        old_ciphertext = await self.client.cover_crypt_encryption(
            "Department::HR && Security Level::Confidential",
            old_message,
            self.pub_key_uid,
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::HR && Security Level::Top Secret",
            self.priv_key_uid,
        )

        # Rekey
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.rotate_cover_crypt_attributes(
            ["Department::HR"],
            self.priv_key_uid,
        )
        self.assertEqual(self.pub_key_uid, new_pub_key_uid)
        self.assertEqual(self.priv_key_uid, new_priv_key_uid)

        new_message = b"My secret data part 2"
        new_ciphertext = await self.client.cover_crypt_encryption(
            "Department::HR && Security Level::Top Secret",
            new_message,
            self.pub_key_uid,
        )

        # Decrypt old message
        plaintext, _ = await self.client.cover_crypt_decryption(
            old_ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), old_message)

        # Decrypt new message
        plaintext, _ = await self.client.cover_crypt_decryption(
            new_ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), new_message)

        # Clear old rotations
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.clear_cover_crypt_attributes_rotations(
            ["Department::HR"],
            self.priv_key_uid,
        )

        # Old message decryption should fail
        with self.assertRaises(Exception):
            plaintext, _ = await self.client.cover_crypt_decryption(
                old_ciphertext,
                user_key_uid,
            )

        # New message can still be decrypted
        plaintext, _ = await self.client.cover_crypt_decryption(
            new_ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), new_message)

    async def test_policy_edit_encryption_decryption(self) -> None:
        # Encryption
        message = b"My secret data part 1"
        ciphertext = await self.client.cover_crypt_encryption(
            "Department::HR && Security Level::Confidential",
            message,
            self.pub_key_uid,
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::HR && Security Level::Top Secret",
            self.priv_key_uid,
        )

        # Disable attribute "Confidential"
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.disable_cover_crypt_attribute(
            "Security Level::Confidential",
            self.priv_key_uid,
        )

        # Confidential message can still be decrypted
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)

        # New encryption with disabled attribute will fail
        with self.assertRaises(Exception):
            await self.client.cover_crypt_encryption(
                "Department::MKG && Security Level::Confidential",
                b"will fail",
                self.pub_key_uid,
            )

        # Rename attribute "FIN"
        # await self.client.rename_cover_crypt_attribute(
        #     'Department::FIN',
        #     'Finance',
        #     self.priv_key_uid,
        # )

        # Add attribute "R&D"
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.add_cover_crypt_attribute(
            "Department::R&D",
            False,
            self.priv_key_uid,
        )

        # Encrypt for new and renamed attribute
        message = b"My secret data part 2"
        ciphertext = await self.client.cover_crypt_encryption(
            "(Department::FIN || Department::R&D) && Security Level::Protected",
            message,
            self.pub_key_uid,
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            "Department::R&D && Security Level::Protected",
            self.priv_key_uid,
        )

        # Decryption as usual
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)


class TestGenericKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient("http://localhost:9998")

    async def test_symmetric_encrypt_decrypt(self):
        # Create
        sym_key_uid = await self.client.create_symmetric_key(256)

        # Export
        sym_key = await self.client.get_object(sym_key_uid)
        self.assertEqual(sym_key.object_type(), "SymmetricKey")
        self.assertEqual(len(sym_key.key_block()), 32)

        # Encrypt
        plaintext = b"Secret message"
        response = await self.client.encrypt(plaintext, sym_key_uid)

        # Decrypt
        decrypted_data = await self.client.decrypt(
            response.data(),
            sym_key_uid,
            iv_counter_nonce=response.iv_counter_nonce(),
            authentication_encryption_tag=response.authenticated_encryption_tag(),
        )
        self.assertEqual(bytes(decrypted_data), plaintext)

        # Revoke
        revoked_uid = await self.client.revoke_key("test", sym_key_uid)
        self.assertEqual(revoked_uid, sym_key_uid)

        # Destroy
        destroyed_uid = await self.client.destroy_key(sym_key_uid)
        self.assertEqual(destroyed_uid, sym_key_uid)

    async def test_key_tags(self):
        # Create key with associated tags
        key_tags = ["top secret", "france"]
        _ = await self.client.create_symmetric_key(256, tags=key_tags)

        # Export
        key_object = await self.client.get_object(key_tags)
        self.assertEqual(key_object.object_type(), "SymmetricKey")
        self.assertEqual(len(key_object.key_block()), 32)

        # Wrong tag
        with self.assertRaises(Exception):
            await self.client.get_object(["wrong"])

        # Encrypt
        plaintext = b"Secret message"
        response = await self.client.encrypt(plaintext, key_tags)

        # Decrypt
        decrypted_data = await self.client.decrypt(
            response.data(),
            key_tags,
            iv_counter_nonce=response.iv_counter_nonce(),
            authentication_encryption_tag=response.authenticated_encryption_tag(),
        )
        self.assertEqual(bytes(decrypted_data), plaintext)

        # Revoke
        await self.client.revoke_key("test", key_tags)

        # Destroy
        await self.client.destroy_key(key_tags)


if __name__ == "__main__":
    unittest.main()
