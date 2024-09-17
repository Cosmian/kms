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


class TestGenericKMS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = KmsClient('http://localhost:9998')

    async def test_symmetric_encrypt_decrypt(self):
        # Create
        sym_key_uid = await self.client.create_symmetric_key(256)

        # Export
        sym_key = await self.client.get_object(sym_key_uid)
        self.assertEqual(sym_key.object_type(), 'SymmetricKey')
        self.assertEqual(len(sym_key.key_block()), 32)

        # Encrypt
        plaintext = b'Secret message'
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
        revoked_uid = await self.client.revoke_key('test', sym_key_uid)
        self.assertEqual(revoked_uid, sym_key_uid)

        # Destroy
        destroyed_uid = await self.client.destroy_key(sym_key_uid)
        self.assertEqual(destroyed_uid, sym_key_uid)

    async def test_key_tags(self):
        # Create key with associated tags
        key_tags = ['top secret', 'france']
        _ = await self.client.create_symmetric_key(256, tags=key_tags)

        # Export
        key_object = await self.client.get_object(key_tags)
        self.assertEqual(key_object.object_type(), 'SymmetricKey')
        self.assertEqual(len(key_object.key_block()), 32)

        # Wrong tag
        with self.assertRaises(Exception):
            await self.client.get_object(['wrong'])

        # Encrypt
        plaintext = b'Secret message'
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
        await self.client.revoke_key('test', key_tags)

        # Destroy
        await self.client.destroy_key(key_tags)


if __name__ == '__main__':
    unittest.main()
