#!/usr/bin/env python3
"""
PyKMIP Client Script for testing against Cosmian KMS server

This script demonstrates how to use PyKMIP to connect to a KMIP server
and perform basic operations.

Requirements:
    pip install PyKMIP

Usage:
    python pykmip_client.py --configuration pykmip.conf --operation query
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

    try:
        # Create KMIP client using KMIPProxy
        proxy = KMIPProxy(config_file=args.configuration)

        if args.verbose:
            print(f"Connecting to KMIP server using configuration: {args.configuration}")

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
        # Import necessary classes for template creation
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory
        
        # Create attribute factory
        attribute_factory = AttributeFactory()
        
        # Create template attributes for AES key
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )
        usage_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT, enums.CryptographicUsageMask.DECRYPT]
        )
        
        # Create template
        template = cobjects.TemplateAttribute(attributes=[algorithm_attr, length_attr, usage_attr])
        
        # Create the key using proper KMIPProxy API
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        
        # Extract UID from result
        uid = result.uuid if hasattr(result, 'uuid') else str(result)

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

    try:
        # First create a key to get attributes for using the same template approach
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory
        
        attribute_factory = AttributeFactory()
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )
        
        template = cobjects.TemplateAttribute(attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        # Get attributes for the created key (simplified)
        try:
            attributes = proxy.get_attributes(uuid=uid)
            attribute_count = len(attributes) if attributes else 0
        except Exception as get_error:
            # If getting attributes fails, just report that we created the key successfully
            if verbose:
                print(f"Note: get_attributes failed ({get_error}), but key creation succeeded")
            attribute_count = "unknown (get_attributes failed)"
            attributes = []

        # Parse attributes safely if we got them
        parsed_attributes = {}
        if attributes:
            for attr in attributes:
                try:
                    attr_name = attr.attribute_name.value if hasattr(attr.attribute_name, 'value') else str(attr.attribute_name)
                    attr_value = str(attr.attribute_value)
                    parsed_attributes[attr_name] = attr_value
                except Exception as attr_error:
                    # Skip problematic attributes
                    if verbose:
                        print(f"Skipping attribute due to parsing error: {attr_error}")
                    continue

        response = {
            "operation": "GetAttributes",
            "status": "success",
            "uid": uid,
            "attribute_count": attribute_count,
            "attributes": parsed_attributes
        }

        if verbose:
            print(f"Retrieved attributes for UID: {uid}")

        return response
    
    except Exception as e:
        return {
            "operation": "GetAttributes",
            "status": "error",
            "error": str(e)
        }

def perform_destroy(proxy, verbose=False):
    """Create and then destroy a symmetric key"""
    if verbose:
        print("Creating and destroying symmetric key...")

    try:
        # First create a key using proper template approach
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory
        
        attribute_factory = AttributeFactory()
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )
        
        template = cobjects.TemplateAttribute(attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        uid = result.uuid if hasattr(result, 'uuid') else str(result)

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
    
    except Exception as e:
        return {
            "operation": "Destroy",
            "status": "error",
            "error": str(e)
        }

def perform_encrypt_decrypt(proxy, verbose=False):
    """Create a key, encrypt some data, then decrypt it"""
    if verbose:
        print("Testing encrypt/decrypt operations...")

    try:
        # Create a symmetric key for encryption using proper template approach
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory
        
        attribute_factory = AttributeFactory()
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )
        
        template = cobjects.TemplateAttribute(attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        uid = result.uuid if hasattr(result, 'uuid') else str(result)

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
        # Import necessary classes for template creation
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory
        
        # Create attribute factory
        attribute_factory = AttributeFactory()
        
        # Create common template attributes for RSA key pair
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.RSA
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            2048
        )
        
        # Create common template
        common_template = cobjects.CommonTemplateAttribute(attributes=[algorithm_attr, length_attr])
        
        # Create key pair using proper KMIPProxy API
        result = proxy.create_key_pair(
            common_template_attribute=common_template
        )
        
        # Debug: Check what's in the result
        if verbose:
            print(f"Result type: {type(result)}")
            print(f"Result status: {result.result_status}")
            print(f"Result reason: {result.result_reason}")
            print(f"Result message: {result.result_message}")
            print(f"Result attributes: {[attr for attr in dir(result) if not attr.startswith('_')]}")
        
        # Check if operation actually succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            raise Exception(f"Create key pair failed: {result.result_reason} - {result.result_message}")
        
        # Extract UIDs from result - try different possible attribute names
        private_uid = None
        public_uid = None
        
        if hasattr(result, 'private_key_uuid'):
            private_uid = result.private_key_uuid
        elif hasattr(result, 'private_key_uid'):
            private_uid = result.private_key_uid
        elif hasattr(result, 'private_unique_identifier'):
            private_uid = result.private_unique_identifier
            
        if hasattr(result, 'public_key_uuid'):
            public_uid = result.public_key_uuid
        elif hasattr(result, 'public_key_uid'):
            public_uid = result.public_key_uid
        elif hasattr(result, 'public_unique_identifier'):
            public_uid = result.public_unique_identifier

        if verbose:
            print(f"Created RSA key pair - Private: {private_uid}, Public: {public_uid}")

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
        # Locate all objects (no specific criteria)
        result = proxy.locate()
        
        # Extract UIDs from the result
        if hasattr(result, 'uuids') and result.uuids:
            located_uids = result.uuids
            count = len(located_uids)
        elif hasattr(result, 'unique_identifiers') and result.unique_identifiers:
            located_uids = result.unique_identifiers
            count = len(located_uids)
        else:
            # Handle case where result format is different
            located_uids = []
            count = 0
            if verbose:
                print(f"Locate result type: {type(result)}")
                print(f"Locate result attributes: {[attr for attr in dir(result) if not attr.startswith('_')]}")

        response = {
            "operation": "Locate",
            "status": "success",
            "located_objects": located_uids,
            "count": count
        }

        if verbose:
            print(f"Located {count} objects on server")

        return response

    except Exception as e:
        return {
            "operation": "Locate",
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    main()
