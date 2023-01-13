# -*- coding: utf-8 -*-
import unittest
from cosmian_kms import KmsClient
from cosmian_cover_crypt import (
    Policy,
    PolicyAxis,
    PublicKey,
    MasterSecretKey,
    UserSecretKey,
)


class TestKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient('http://localhost:9998')

        # Create Policy
        self.policy = Policy()
        self.policy.add_axis(
            PolicyAxis(
                'Security Level',
                ['Protected', 'Confidential', 'Top Secret'],
                hierarchical=True,
            )
        )
        self.policy.add_axis(
            PolicyAxis('Department', ['FIN', 'MKG', 'HR'], hierarchical=False)
        )

        # Generate master key pair
        (
            self.pubkey_uid,
            self.privkey_uid,
        ) = await self.client.create_cover_crypt_master_key_pair(self.policy.to_json())

    async def test_master_keys(self) -> None:
        # Query public key from KMS
        pubkey = await self.client.get_object(self.pubkey_uid)
        self.assertEqual(pubkey.object_type(), 'PublicKey')
        self.assertIsInstance(PublicKey.from_bytes(pubkey.key_block()), PublicKey)

        # Query private key from KMS
        privkey = await self.client.get_object(self.privkey_uid)
        self.assertEqual(privkey.object_type(), 'PrivateKey')
        self.assertIsInstance(
            MasterSecretKey.from_bytes(privkey.key_block()), MasterSecretKey
        )

        # Import custom private key
        custom_privkey_uid = (
            await self.client.import_cover_crypt_master_private_key_request(
                privkey.key_block(),
                True,
                self.pubkey_uid,
                self.policy.to_json(),
                False,
                None,
                'my_custom_privkey',
            )
        )
        self.assertEqual(custom_privkey_uid, 'my_custom_privkey')

        # Import custom public key
        custom_pubkey_uid = await self.client.import_cover_crypt_public_key_request(
            pubkey.key_block(),
            True,
            self.policy.to_json(),
            self.privkey_uid,
            'my_custom_pubkey',
        )
        self.assertEqual(custom_pubkey_uid, 'my_custom_pubkey')

    async def test_user_key_generation(self) -> None:
        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::MKG && Security Level::Confidential', self.privkey_uid
        )

        # Query private key from KMS
        userkey = await self.client.get_object(userkey_uid)
        self.assertEqual(userkey.object_type(), 'PrivateKey')
        self.assertIsInstance(
            UserSecretKey.from_bytes(userkey.key_block()), UserSecretKey
        )

        # Import custom user key
        custom_userkey_uid = (
            await self.client.import_cover_crypt_user_decryption_key_request(
                userkey.key_block(),
                True,
                self.privkey_uid,
                'Department::MKG && Security Level::Confidential',
                False,
                None,
                'my_custom_userkey',
            )
        )
        self.assertEqual(custom_userkey_uid, 'my_custom_userkey')

        # Revoke key
        revoked_uid = await self.client.revoke_cover_crypt_key(userkey_uid, 'test')
        self.assertEqual(revoked_uid, userkey_uid)

        # Destroy key
        destroyed_uid = await self.client.destroy_cover_crypt_key(userkey_uid)
        self.assertEqual(destroyed_uid, userkey_uid)

    async def test_simple_encryption_decryption_without_metadata(self) -> None:
        # Encryption
        to_encrypt = b'My secret data'
        protected_mkg_ciphertext = await self.client.cover_crypt_encryption(
            self.pubkey_uid,
            'Department::MKG && Security Level::Protected',
            to_encrypt,
        )

        topsecret_mkg_ciphertext = await self.client.cover_crypt_encryption(
            self.pubkey_uid,
            'Department::MKG && Security Level::Top Secret',
            to_encrypt,
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::MKG && Security Level::Confidential', self.privkey_uid
        )

        # Successful decryption
        plaintext, _ = await self.client.cover_crypt_decryption(
            userkey_uid,
            protected_mkg_ciphertext,
        )
        self.assertEqual(bytes(plaintext), to_encrypt)

        # Wrong permission
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                userkey_uid,
                topsecret_mkg_ciphertext,
            )

    async def test_simple_encryption_decryption_with_metadata(self) -> None:
        # Encryption
        to_encrypt = b'My secret data'
        protected_fin_ciphertext = await self.client.cover_crypt_encryption(
            self.pubkey_uid,
            'Department::FIN && Security Level::Protected',
            to_encrypt,
            header_metadata=b'header message',
            authentication_data=b'auth token',
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::FIN && Security Level::Protected', self.privkey_uid
        )

        # Successful decryption
        plaintext, header = await self.client.cover_crypt_decryption(
            userkey_uid,
            protected_fin_ciphertext,
            authentication_data=b'auth token',
        )
        self.assertEqual(bytes(plaintext), to_encrypt)
        self.assertEqual(bytes(header), b'header message')

        # Missing authentication data
        with self.assertRaises(Exception):
            await self.client.cover_crypt_decryption(
                userkey_uid,
                protected_fin_ciphertext,
            )

    async def test_policy_rotation_encryption_decryption(self) -> None:
        # Encryption
        old_message = b'My secret data part 1'
        old_ciphertext = await self.client.cover_crypt_encryption(
            self.pubkey_uid,
            'Department::HR && Security Level::Confidential',
            old_message,
        )

        # Generate user key
        userkey_uid = await self.client.create_cover_crypt_user_decryption_key(
            'Department::HR && Security Level::Top Secret', self.privkey_uid
        )

        # Rekey
        (
            new_pubkey_uid,
            new_privkey_uid,
        ) = await self.client.rotate_cover_crypt_attributes(
            self.privkey_uid, ['Department::HR']
        )
        self.assertEqual(self.pubkey_uid, new_pubkey_uid)
        self.assertEqual(self.privkey_uid, new_privkey_uid)

        new_message = b'My secret data part 2'
        new_ciphertext = await self.client.cover_crypt_encryption(
            self.pubkey_uid,
            'Department::HR && Security Level::Top Secret',
            new_message,
        )

        # Decrypt old message
        plaintext, _ = await self.client.cover_crypt_decryption(
            userkey_uid,
            old_ciphertext,
        )
        self.assertEqual(bytes(plaintext), old_message)

        # Decrypt new message
        plaintext, _ = await self.client.cover_crypt_decryption(
            userkey_uid,
            new_ciphertext,
        )
        self.assertEqual(bytes(plaintext), new_message)


if __name__ == '__main__':
    unittest.main()
