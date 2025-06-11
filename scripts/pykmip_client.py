#!/usr/bin/env python3
"""
PyKMIP Client Script for testing against Cosmian KMS server

This script demonstrates how to use PyKMIP to connect to a KMIP server
and perform basic operations like Query.

Requirements:
    pip install PyKMIP

Usage:
    python pykmip_client.py --host 127.0.0.1 --port 5696 --cert client.crt --key client.key --ca ca.crt
"""

import argparse
import sys
import json
from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums



def main():
    parser = argparse.ArgumentParser(description='PyKMIP Client for KMIP Server Testing')
    parser.add_argument('--configuration', required=True, help='Configuration file path')
    parser.add_argument('--operation', default='query', 
                       choices=['query', 'create', 'get', 'destroy', 'encrypt_decrypt', 'create_keypair', 'locate'],
                       help='KMIP operation to perform')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose output')

    args = parser.parse_args()

    print(f"Using configuration file: {args.configuration}")

    try:
        # Create KMIP client using KMIPProxy directly (more reliable)
        # Use minimal SSL verification for testing
        proxy = KMIPProxy(
            config_file=args.configuration
        )


        if args.verbose:
            print(f"Connecting to KMIP server at {args.host}:{args.port}")
            print(f"Using certificates: cert={args.cert}, key={args.key}")

        # Open connection
        proxy.open()

        # Perform the requested operation
        if args.operation == 'query':
            result = perform_query(proxy, args.verbose)
        elif args.operation == 'create':
            result = perform_create_symmetric_key(proxy, args.verbose)
        elif args.operation == 'get':
            result = perform_get_attributes(proxy, args.verbose)
        elif args.operation == 'destroy':
            result = perform_destroy(proxy, args.verbose)
        elif args.operation == 'encrypt_decrypt':
            result = perform_encrypt_decrypt(proxy, args.verbose)
        elif args.operation == 'create_keypair':
            result = perform_create_keypair(proxy, args.verbose)
        elif args.operation == 'locate':
            result = perform_locate(proxy, args.verbose)
        else:
            print(f"Unsupported operation: {args.operation}")
            sys.exit(1)

        # Output result as JSON for easy parsing
        print(json.dumps(result, indent=2))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        if 'proxy' in locals():
            proxy.close()


def perform_query(proxy, verbose=False):
    """Perform a Query operation to discover server capabilities"""
    if verbose:
        print("Performing Query operation...")

    # Query for server information using QueryFunction enums
    result = proxy.query(
        query_functions=[
            enums.QueryFunction.QUERY_OBJECTS,
            enums.QueryFunction.QUERY_OPERATIONS,
            enums.QueryFunction.QUERY_SERVER_INFORMATION,
            enums.QueryFunction.QUERY_APPLICATION_NAMESPACES,
            enums.QueryFunction.QUERY_EXTENSION_LIST,
            enums.QueryFunction.QUERY_CAPABILITIES
        ]
    )

    response = {
        "operation": "Query",
        "status": "success",
        "objects": result.objects if hasattr(result, 'objects') else [],
        "operations": [op.value for op in result.operations] if hasattr(result, 'operations') else [],
        "server_information": result.server_information if hasattr(result, 'server_information') else {},
        "namespaces": result.namespaces if hasattr(result, 'namespaces') else [],
        "extensions": result.extensions if hasattr(result, 'extensions') else [],
        "capabilities": result.capabilities if hasattr(result, 'capabilities') else []
    }

    if verbose:
        print("Query operation completed successfully")

    return response


def perform_create_symmetric_key(proxy, verbose=False):
    """Create a symmetric key"""
    if verbose:
        print("Creating symmetric key...")

    try:
        # Create a 256-bit AES key
        uid = proxy.create(
            enums.CryptographicAlgorithm.AES,
            256,
            usage_masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )

        response = {
            "operation": "Create",
            "status": "success",
            "uid": uid,
            "algorithm": "AES",
            "length": 256
        }

        if verbose:
            print(f"Created symmetric key with UID: {uid}")

        return response
    
    except Exception as e:
        return {
            "operation": "Create",
            "status": "error",
            "error": str(e)
        }


def perform_get_attributes(proxy, verbose=False):
    """Get attributes for a specific object"""
    if verbose:
        print("Getting object attributes...")

    # First create a key to get attributes for
    uid = proxy.create(
        enums.CryptographicAlgorithm.AES,
        256
    )

    # Get attributes for the created key
    attributes = proxy.get_attributes(uid=uid)

    response = {
        "operation": "GetAttributes",
        "status": "success",
        "uid": uid,
        "attributes": {
            attr.attribute_name.value: str(attr.attribute_value) 
            for attr in attributes
        }
    }

    if verbose:
        print(f"Retrieved attributes for UID: {uid}")

    return response


def perform_destroy(proxy, verbose=False):
    """Create and then destroy a symmetric key"""
    if verbose:
        print("Creating and destroying symmetric key...")

    # First create a key
    uid = proxy.create(
        enums.CryptographicAlgorithm.AES,
        256
    )

    if verbose:
        print(f"Created key with UID: {uid}")

    # Then destroy it
    proxy.destroy(uid)

    response = {
        "operation": "Destroy",
        "status": "success",
        "uid": uid,
        "message": "Key created and destroyed successfully"
    }

    if verbose:
        print(f"Destroyed key with UID: {uid}")

    return response


def perform_encrypt_decrypt(proxy, verbose=False):
    """Create a key, encrypt some data, then decrypt it"""
    if verbose:
        print("Testing encrypt/decrypt operations...")

    try:
        # Create a symmetric key for encryption
        uid = proxy.create(
            enums.CryptographicAlgorithm.AES,
            256,
            usage_masks=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )

        if verbose:
            print(f"Created encryption key with UID: {uid}")

        # Test data to encrypt
        test_data = b"Hello, PyKMIP from Rust!"
        
        # Encrypt the data
        encrypt_result = proxy.encrypt(
            uid,
            data=test_data,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5
            }
        )

        if verbose:
            print("Data encrypted successfully")

        # Decrypt the data
        decrypt_result = proxy.decrypt(
            uid,
            data=encrypt_result.data,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_parameters={
                'block_cipher_mode': enums.BlockCipherMode.CBC,
                'padding_method': enums.PaddingMethod.PKCS5
            }
        )

        if verbose:
            print("Data decrypted successfully")

        # Verify the decrypted data matches original
        success = decrypt_result.data == test_data

        response = {
            "operation": "EncryptDecrypt",
            "status": "success" if success else "error",
            "uid": uid,
            "original_data": test_data.hex(),
            "encrypted_data": encrypt_result.data.hex(),
            "decrypted_data": decrypt_result.data.hex(),
            "verification": "passed" if success else "failed"
        }

        # Clean up - destroy the test key
        proxy.destroy(uid)

        return response

    except Exception as e:
        return {
            "operation": "EncryptDecrypt", 
            "status": "error",
            "error": str(e)
        }


def perform_create_keypair(proxy, verbose=False):
    """Create an RSA key pair"""
    if verbose:
        print("Creating RSA key pair...")

    try:
        # Create RSA key pair
        private_uid, public_uid = proxy.create_key_pair(
            enums.CryptographicAlgorithm.RSA,
            2048,
            usage_masks=[
                enums.CryptographicUsageMask.SIGN,
                enums.CryptographicUsageMask.VERIFY
            ]
        )

        response = {
            "operation": "CreateKeyPair",
            "status": "success",
            "private_key_uid": private_uid,
            "public_key_uid": public_uid,
            "algorithm": "RSA",
            "length": 2048
        }

        if verbose:
            print(f"Created RSA key pair - Private: {private_uid}, Public: {public_uid}")

        return response

    except Exception as e:
        return {
            "operation": "CreateKeyPair",
            "status": "error", 
            "error": str(e)
        }


def perform_locate(proxy, verbose=False):
    """Locate objects on the server"""
    if verbose:
        print("Locating objects on server...")

    try:
        # First create a test object so we have something to locate
        uid = proxy.create(
            enums.CryptographicAlgorithm.AES,
            256,
            usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
        )

        # Now locate objects
        located_uids = proxy.locate()

        response = {
            "operation": "Locate",
            "status": "success",
            "created_uid": uid,
            "located_objects": located_uids,
            "total_objects": len(located_uids)
        }

        if verbose:
            print(f"Located {len(located_uids)} objects on server")

        return response

    except Exception as e:
        return {
            "operation": "Locate",
            "status": "error",
            "error": str(e)
        }


if __name__ == "__main__":
    main()
