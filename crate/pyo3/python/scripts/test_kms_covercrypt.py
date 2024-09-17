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
        self.client = KmsClient('http://localhost:9998')

        # Create Policy
        # Warning: the policy bytes format depends on the last released version of covercrypt on PyPI
        self.policy = Policy()
        self.policy.add_axis(
            PolicyAxis(
                'Security Level',
                [
                    ('Protected', False),
                    ('Confidential', True),
                    ('Top Secret', True),
                ],
                hierarchical=True,
            )
        )
        self.policy.add_axis(
            PolicyAxis(
                'Department',
                [('FIN', False), ('MKG', False), ('HR', False)],
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
        self.assertEqual(pub_key.object_type(), 'PublicKey')
        self.assertIsInstance(
            MasterPublicKey.from_bytes(pub_key.key_block()), MasterPublicKey
        )

        # Query private key from KMS
        priv_key = await self.client.get_object(self.priv_key_uid)
        self.assertEqual(priv_key.object_type(), 'PrivateKey')
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
            'my_custom_priv_key',
        )
        self.assertEqual(custom_priv_key_uid, 'my_custom_priv_key')

        # Import custom public key
        custom_pub_key_uid = await self.client.import_cover_crypt_public_key(
            pub_key.key_block(),
            True,
            self.policy.to_bytes(),
            self.priv_key_uid,
            'my_custom_pub_key',
        )
        self.assertEqual(custom_pub_key_uid, 'my_custom_pub_key')

    async def test_user_key_generation(self) -> None:
        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::MKG && Security Level::Confidential',
            self.priv_key_uid,
        )

        # Query private key from KMS
        user_key = await self.client.get_object(user_key_uid)
        self.assertEqual(user_key.object_type(), 'PrivateKey')
        self.assertIsInstance(
            UserSecretKey.from_bytes(user_key.key_block()), UserSecretKey
        )

        # Import custom user key
        custom_user_key_uid = await self.client.import_cover_crypt_user_decryption_key(
            user_key.key_block(),
            True,
            self.priv_key_uid,
            'Department::MKG && Security Level::Confidential',
            None,
            False,
            None,
            'my_custom_user_key',
        )
        self.assertEqual(custom_user_key_uid, 'my_custom_user_key')

        # Revoke key
        revoked_uid = await self.client.revoke_key('test', user_key_uid)
        self.assertEqual(revoked_uid, user_key_uid)

        # Destroy key
        destroyed_uid = await self.client.destroy_key(user_key_uid)
        self.assertEqual(destroyed_uid, user_key_uid)

    async def test_simple_encryption_decryption_without_metadata(self) -> None:
        # Encryption
        to_encrypt = b'My secret data'
        protected_mkg_ciphertext = await self.client.cover_crypt_encryption(
            'Department::MKG && Security Level::Protected',
            to_encrypt,
            self.pub_key_uid,
        )

        top_secret_mkg_ciphertext = await self.client.cover_crypt_encryption(
            'Department::MKG && Security Level::Top Secret',
            to_encrypt,
            self.pub_key_uid,
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::MKG && Security Level::Confidential',
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
                top_secret_mkg_ciphertext,
                user_key_uid,
            )

    async def test_simple_encryption_decryption_with_metadata(self) -> None:
        # Encryption
        to_encrypt = b'My secret data'
        protected_fin_ciphertext = await self.client.cover_crypt_encryption(
            'Department::FIN && Security Level::Protected',
            to_encrypt,
            self.pub_key_uid,
            header_metadata=b'header message',
            authentication_data=b'auth token',
        )

        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::FIN && Security Level::Protected',
            self.priv_key_uid,
        )

        # Successful decryption
        plaintext, header = await self.client.cover_crypt_decryption(
            protected_fin_ciphertext,
            user_key_uid,
            authentication_data=b'auth token',
        )
        self.assertEqual(bytes(plaintext), to_encrypt)
        self.assertEqual(bytes(header), b'header message')

        # Missing authentication data
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                protected_fin_ciphertext,
                user_key_uid,
            )

    async def test_policy_rotation_encryption_decryption(self) -> None:
        # Encryption
        old_message = b'My secret data part 1'
        old_ciphertext = await self.client.cover_crypt_encryption(
            'Department::HR && Security Level::Confidential',
            old_message,
            self.pub_key_uid,
        )

        user_access_policy = 'Department::HR && Security Level::Top Secret'
        # Generate user key
        user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            user_access_policy,
            self.priv_key_uid,
        )

        # Rekey all keys related to `Department::HR`
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.rekey_cover_crypt_access_policy(
            'Department::HR',
            self.priv_key_uid,
        )
        self.assertEqual(self.pub_key_uid, new_pub_key_uid)
        self.assertEqual(self.priv_key_uid, new_priv_key_uid)

        new_message = b'My secret data part 2'
        new_ciphertext = await self.client.cover_crypt_encryption(
            user_access_policy,
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

        # Prune old keys
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.prune_cover_crypt_access_policy(
            'Department::HR',
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
        # Generate user key
        fin_user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::FIN && Security Level::Top Secret',
            self.priv_key_uid,
        )
        message = b'My secret data'

        # Rename attribute "FIN"
        await self.client.rename_cover_crypt_attribute(
            'Department::FIN',
            'Finance',
            self.priv_key_uid,
        )

        # Add attribute "R&D"
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.add_cover_crypt_attribute(
            'Department::R&D',
            False,
            self.priv_key_uid,
        )

        # Adding attribute to ordered dimension is not supported
        with self.assertRaises(Exception):
            await self.client.add_cover_crypt_attribute(
                'Security Level::New', False, self.priv_key_uid
            )

        # Encrypt for new and renamed attribute
        message = b'My secret data part 2'
        ciphertext = await self.client.cover_crypt_encryption(
            '(Department::Finance || Department::R&D) && Security Level::Protected',
            message,
            self.pub_key_uid,
        )

        # Generate user key
        rd_user_key_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::R&D && Security Level::Protected',
            self.priv_key_uid,
        )

        # Decryption with finance user
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            fin_user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)

        # Decryption with R&D user
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            rd_user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)

        # Disable attribute "Confidential"
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.disable_cover_crypt_attribute(
            'Security Level::Confidential',
            self.priv_key_uid,
        )

        # Confidential message can still be decrypted
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            fin_user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)

        # New encryption with disabled attribute will fail
        with self.assertRaises(Exception):
            await self.client.cover_crypt_encryption(
                'Department::MKG && Security Level::Confidential',
                b'will fail',
                self.pub_key_uid,
            )

        # Remove attribute "Finance"
        (
            new_pub_key_uid,
            new_priv_key_uid,
        ) = await self.client.remove_cover_crypt_attribute(
            'Department::Finance',
            self.priv_key_uid,
        )

        # Finance users can no longer decrypt ciphertext
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                ciphertext,
                fin_user_key_uid,
            )

        # R&D users can still decrypt its ciphertext
        plaintext, _ = await self.client.cover_crypt_decryption(
            ciphertext,
            rd_user_key_uid,
        )
        self.assertEqual(bytes(plaintext), message)

        # Removing attribute from ordered dimension is not supported
        with self.assertRaises(Exception):
            await self.client.remove_cover_crypt_attribute(
                'Security Level::Confidential', self.priv_key_uid
            )


if __name__ == '__main__':
    unittest.main()
