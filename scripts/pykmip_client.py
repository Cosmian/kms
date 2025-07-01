#!/usr/bin/env python3
"""
PyKMIP Client Script for testing against Cosmian KMS server

This script demonstrates how to use PyKMIP to connect to a KMIP server
and perform basic operations.

Requirements:
    pip install PyKMIP
    Python 3.11 or earlier (due to ssl.wrap_socket deprecation in 3.12+)

Usage:
    python pykmip_client.py --configuration pykmip.conf --operation query
"""

import argparse
import sys
import json
import traceback

# Check Python version before importing PyKMIP
if sys.version_info >= (3, 12):
    print(json.dumps({
        "operation": "Version Check",
        "status": "error",
        "error": f"Python {sys.version_info.major}.{sys.version_info.minor} is not supported. PyKMIP requires Python 3.11 or earlier due to ssl.wrap_socket deprecation.",
        "solution": "Install Python 3.11 and recreate virtual environment: rm -rf .venv && python3.11 -m venv .venv && source .venv/bin/activate && pip install PyKMIP"
    }, indent=2))
    sys.exit(1)

try:
    from kmip.services.kmip_client import KMIPProxy
    from kmip.core import enums
except ImportError as e:
    print(json.dumps({
        "operation": "Import Check",
        "status": "error",
        "error": f"Failed to import PyKMIP: {str(e)}",
        "solution": "Install PyKMIP: pip install PyKMIP"
    }, indent=2))
    sys.exit(1)
except Exception as e:
    # Catch SSL-related errors that might occur during import
    if "wrap_socket" in str(e):
        print(json.dumps({
            "operation": "SSL Check",
            "status": "error",
            "error": f"SSL compatibility issue: {str(e)}",
            "solution": "Use Python 3.11 or earlier. Current Python version has removed ssl.wrap_socket which PyKMIP requires."
        }, indent=2))
        sys.exit(1)
    else:
        print(json.dumps({
            "operation": "Import Check",
            "status": "error",
            "error": f"Unexpected import error: {str(e)}"
        }, indent=2))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='PyKMIP Client for KMIP Server Testing')
    parser.add_argument('--configuration', required=True,
                        help='Configuration file path')
    parser.add_argument('--operation', default='query',
                        choices=['activate', 'create', 'create_keypair', 'decrypt', 'destroy',
                                 'discover_versions', 'encrypt', 'get', 'get_attributes', 'locate', 'mac', 'query',
                                 'revoke'],
                        help='KMIP operation to perform')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    try:
        # Create KMIP client using KMIPProxy
        proxy = KMIPProxy(config_file=args.configuration)

        if args.verbose:
            print(
                f"Connecting to KMIP server using configuration: {args.configuration}")

        # Open connection
        proxy.open()

        # Perform the requested operation with proper exception handling
        try:
            if args.operation == 'activate':
                result = perform_activate(proxy, args.verbose)
            # Certify operation is not implemented in PyKMIP,
            # the solution in this script is a workaround that simulates certification
            # nd uses operations not (yet) implemented in the KMS => Comment out
            # elif args.operation == 'certify':
            #     from pykmip_certify import perform_certify
            #     result = perform_certify(proxy, args.verbose)
            elif args.operation == 'create':
                result = perform_create_symmetric_key(proxy, args.verbose)
            elif args.operation == 'create_keypair':
                result = perform_create_keypair(proxy, args.verbose)
            elif args.operation == 'decrypt':
                result = perform_decrypt(proxy, args.verbose)
            elif args.operation == 'destroy':
                result = perform_destroy(proxy, args.verbose)
            elif args.operation == 'discover_versions':
                result = perform_discover_versions(proxy, args.verbose)
            elif args.operation == 'encrypt':
                result = perform_encrypt(proxy, args.verbose)
            elif args.operation == 'get':
                result = perform_get(proxy, args.verbose)
            elif args.operation == 'get_attributes':
                result = perform_get_attributes(proxy, args.verbose)
            elif args.operation == 'locate':
                result = perform_locate(proxy, args.verbose)
            elif args.operation == 'mac':
                result = perform_mac(proxy, args.verbose)
            elif args.operation == 'query':
                result = perform_query(proxy, args.verbose)
            elif args.operation == 'revoke':
                result = perform_revoke(proxy, args.verbose)
            else:
                result = {
                    "operation": args.operation,
                    "status": "error",
                    "error": f"Unsupported operation: {args.operation}"
                }

            # Output result as JSON for easy parsing
            print(json.dumps(result, indent=2))

        except Exception as operation_error:
            # Catch any unhandled exceptions from operations
            error_result = {
                "operation": args.operation,
                "status": "error",
                "error": f"Unhandled exception in {args.operation} operation: {str(operation_error)}",
                "exception_type": type(operation_error).__name__
            }

            if args.verbose:
                error_result["full_traceback"] = traceback.format_exc()

            print(json.dumps(error_result, indent=2))
            sys.exit(1)

    except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError, TypeError, IOError) as e:
        error_msg = str(e)

        # Check for SSL-related errors
        if "wrap_socket" in error_msg:
            result = {
                "operation": args.operation,
                "status": "error",
                "error": "SSL compatibility issue - ssl.wrap_socket not available",
                "technical_details": error_msg,
                "solution": "Use Python 3.11 or earlier. PyKMIP is not compatible with Python 3.12+ due to ssl.wrap_socket removal."
            }
        else:
            result = {
                "operation": args.operation,
                "status": "error",
                "error": f"Connection or configuration error: {error_msg}"
            }

        print(json.dumps(result, indent=2))
        sys.exit(1)

    except Exception as unexpected_error:
        # Catch any completely unexpected errors
        result = {
            "operation": args.operation,
            "status": "error",
            "error": f"Unexpected error: {str(unexpected_error)}",
            "exception_type": type(unexpected_error).__name__
        }

        if args.verbose:
            result["full_traceback"] = traceback.format_exc()

        print(json.dumps(result, indent=2))
        sys.exit(1)

    finally:
        if 'proxy' in locals():
            try:
                proxy.close()
            except Exception:
                pass  # Ignore errors during cleanup


def perform_query(proxy, verbose=False):
    """Perform a Query operation to discover server capabilities"""
    if verbose:
        print("Performing Query operation...")

    try:
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

        # Check if query operation succeeded
        if hasattr(result, 'result_status'):
            if result.result_status.value == enums.ResultStatus.SUCCESS:
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
            else:
                # Query failed
                error_msg = f"Query operation failed: {result.result_reason}"
                if hasattr(result, 'result_message') and result.result_message:
                    error_msg += f" - {result.result_message}"

                response = {
                    "operation": "Query",
                    "status": "error",
                    "error": error_msg
                }
        else:
            # Fallback - assume success if no status field (shouldn't happen)
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

    # Catch specific exceptions we expect might occur during query
    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Query",
            "status": "error",
            "error": str(e)
        }


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
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT]
        )

        # Create template
        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr, usage_attr])

        # Create the key using proper KMIPProxy API
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation actually succeeded
        if hasattr(result, 'result_status'):
            if result.result_status.value == enums.ResultStatus.SUCCESS:
                # Extract UID from successful result
                uid = result.uuid if hasattr(result, 'uuid') else str(result)

                response = {
                    "operation": "Create",
                    "status": "success",
                    "uid": uid,
                    "algorithm": "AES",
                    "length": 256
                }
            else:
                # Create failed
                error_msg = f"Create operation failed: {result.result_reason}"
                if hasattr(result, 'result_message') and result.result_message:
                    error_msg += f" - {result.result_message}"

                response = {
                    "operation": "Create",
                    "status": "error",
                    "error": error_msg
                }
        else:
            # Fallback - assume success if no status field (shouldn't happen)
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

    except (ValueError, AttributeError, TypeError) as e:
        return {
            "operation": "Create",
            "status": "error",
            "error": str(e)
        }
    except ConnectionError as e:
        return {
            "operation": "Create",
            "status": "error",
            "error": f"Connection error: {str(e)}"
        }
    # pylint: disable=broad-exception-caught
    except Exception as e:  # Still catch any unexpected exceptions as fallback
        return {
            "operation": "Create",
            "status": "error",
            "error": f"Unexpected error: {str(e)}"
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

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded first
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            # Create failed
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "GetAttributes",
                "status": "error",
                "error": error_msg
            }

        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        # Get attributes for the created key
        try:
            # First try to get specific attributes that we know PyKMIP supports
            supported_attributes = [
                "Cryptographic Algorithm",
                "Cryptographic Length",
                "Cryptographic Usage Mask",
                "State",
                "Unique Identifier"
            ]

            attributes_result = proxy.get_attributes(
                uuid=uid, attribute_names=supported_attributes)

            # Extract attributes from the result object
            if hasattr(attributes_result, 'attributes'):
                attributes = attributes_result.attributes
            else:
                # Debug what's in the result
                if verbose:
                    print(
                        f"GetAttributes result type: {type(attributes_result)}")
                    print(
                        f"Result attributes: {[attr for attr in dir(attributes_result) if not attr.startswith('_')]}")
                attributes = []

            # Parse attributes safely
            parsed_attributes = {}
            for attr in attributes:
                try:
                    attr_name = attr.attribute_name.value if hasattr(
                        attr.attribute_name, 'value') else str(attr.attribute_name)
                    attr_value = str(attr.attribute_value)
                    parsed_attributes[attr_name] = attr_value
                except (ValueError, AttributeError, TypeError) as attr_error:
                    if verbose:
                        print(
                            f"Skipping attribute due to parsing error: {attr_error}")
                    continue

            response = {
                "operation": "GetAttributes",
                "status": "success",
                "uid": uid,
                "attribute_count": len(parsed_attributes),
                "attributes": parsed_attributes
            }

        except (ValueError, AttributeError, TypeError, ConnectionError, IOError) as get_error:
            # If getting specific attributes fails, report the actual error
            error_msg = str(get_error)
            if "No value type for COMMENT" in error_msg:
                error_msg = "PyKMIP doesn't support COMMENT attribute (KMIP 2.1 extension used by Cosmian KMS)"

            response = {
                "operation": "GetAttributes",
                "status": "error",
                "uid": uid,
                "error": error_msg,
                "note": "Key was created successfully, but attribute retrieval failed"
            }

        if verbose:
            print(f"Retrieved attributes for UID: {uid}")

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError, TypeError, IOError) as e:
        return {
            "operation": "GetAttributes",
            "status": "error",
            "error": str(e)
        }


def perform_destroy(proxy, verbose=False):
    """Create a symmetric key, revoke it, then destroy it"""
    if verbose:
        print("Creating, revoking, and destroying symmetric key...")

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

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "Destroy",
                "status": "error",
                "error": error_msg
            }

        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        if verbose:
            print(f"Created key with UID: {uid}")

        # First revoke the key before destroying
        if verbose:
            print(f"Revoking key with UID: {uid}")

        revoke_result = proxy.revoke(
            revocation_reason=enums.RevocationReasonCode.CESSATION_OF_OPERATION,
            uuid=uid,
            revocation_message="Key being prepared for destruction"
        )

        # Check if revoke succeeded
        revoke_success = True
        revoke_error = None

        if hasattr(revoke_result, 'result_status'):
            if revoke_result.result_status.value != enums.ResultStatus.SUCCESS:
                revoke_success = False
                revoke_error = f"Revoke failed: {revoke_result.result_reason}"
                if hasattr(revoke_result, 'result_message') and revoke_result.result_message:
                    revoke_error += f" - {revoke_result.result_message}"

                if verbose:
                    print(f"Warning: {revoke_error}")

        if verbose and revoke_success:
            print(f"Revoked key with UID: {uid}")

        # Then destroy it
        destroy_result = proxy.destroy(uuid=uid)

        # Check if destroy actually succeeded
        if hasattr(destroy_result, 'result_status'):
            if destroy_result.result_status.value == enums.ResultStatus.SUCCESS:
                response = {
                    "operation": "Destroy",
                    "status": "success",
                    "uid": uid,
                    "revoke_success": revoke_success,
                    "message": f"Key created, {'revoked, ' if revoke_success else 'revoke failed, '}and destroyed successfully"
                }

                if revoke_error:
                    response["revoke_error"] = revoke_error

            else:
                # Destroy failed
                error_msg = f"Destroy operation failed: {destroy_result.result_reason}"
                if hasattr(destroy_result, 'result_message') and destroy_result.result_message:
                    error_msg += f" - {destroy_result.result_message}"

                response = {
                    "operation": "Destroy",
                    "status": "error",
                    "uid": uid,
                    "error": error_msg,
                    "revoke_success": revoke_success,
                    "note": f"Key was created and {'revoked' if revoke_success else 'revoke attempted'} but destroy failed"
                }

                if revoke_error:
                    response["revoke_error"] = revoke_error
        else:
            # Fallback if result structure is unexpected
            response = {
                "operation": "Destroy",
                "status": "success",
                "uid": uid,
                "revoke_success": revoke_success,
                "message": f"Key created, {'revoked, ' if revoke_success else 'revoke failed, '}and destroyed successfully (result status unknown)"
            }

            if revoke_error:
                response["revoke_error"] = revoke_error

        if verbose:
            print(f"Destroyed key with UID: {uid}")

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Destroy",
            "status": "error",
            "error": str(e)
        }


def perform_decrypt(proxy: KMIPProxy, verbose=False):
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
            enums.CryptographicAlgorithm.AES,
        )
        # Use GCM mode for encryption - PyKMIP doen't support the BlockCipherMode attribute
        # The KMS will default to AES-GCM if no mode is specified
        # blockcipher_mode_attr = attribute_factory.create_attribute(
        #     enums.AttributeType.BLOCK_CIPHER_MODE,
        #     enums.BlockCipherMode.GCM
        # )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        if verbose:
            print(f"Created encryption key with UID: {uid}")

        # Test data to encrypt
        test_data = b"Hello, PyKMIP from Rust!"

        try:
            # Encrypt the data (use default parameters)
            encrypt_result = proxy.encrypt(
                data=test_data,
                unique_identifier=uid
            )

            ciphertext = encrypt_result['data'] if 'data' in encrypt_result else None
            iv_counter_nonce = encrypt_result.get('iv_counter_nonce', None)

            if verbose:
                print("Data encrypted successfully")

            # Decrypt the data
            decrypt_result = proxy.decrypt(
                data=ciphertext,
                iv_counter_nonce=iv_counter_nonce,
                unique_identifier=uid
            )

            if verbose:
                print("Data decrypted successfully")

            # Verify the decrypted data matches original
            success = decrypt_result['data'] == test_data

            response = {
                "operation": "Decrypt",
                "status": "success" if success else "error",
                "uid": uid,
                "original_data ": test_data.hex(),
                "encrypted_data": encrypt_result['data'].hex(),
                "decrypted_data": decrypt_result['data'].hex(),
                "verification  ": "passed" if success else "failed"
            }

        except (ValueError, TypeError, AttributeError, ConnectionError, IOError) as crypto_error:
            error_msg = str(crypto_error)
            response = {
                "operation": "Decrypt",
                "status": "error",
                "uid": uid,
                "error": error_msg
            }

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Decrypt",
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
        common_template = cobjects.CommonTemplateAttribute(
            attributes=[algorithm_attr, length_attr])

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
            print(
                f"Result attributes: {[attr for attr in dir(result) if not attr.startswith('_')]}")

        # Check if operation actually succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            raise ValueError(
                f"Create key pair failed: {result.result_reason} - {result.result_message}")

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
            print(
                f"Created RSA key pair - Private: {private_uid}, Public: {public_uid}")

        response = {
            "operation": "CreateKeyPair",
            "status": "success",
            "private_key_uid": private_uid,
            "public_key_uid": public_uid,
            "algorithm": "RSA",
            "length": 2048
        }

        if verbose:
            print(
                f"Created RSA key pair - Private: {private_uid}, Public: {public_uid}")

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
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

        # Check if locate operation succeeded
        if hasattr(result, 'result_status'):
            if result.result_status.value == enums.ResultStatus.SUCCESS:
                # Extract UIDs from the successful result
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
                        print(
                            f"Locate result attributes: {[attr for attr in dir(result) if not attr.startswith('_')]}")

                response = {
                    "operation": "Locate",
                    "status": "success",
                    "located_objects": located_uids,
                    "count": count
                }
            else:
                # Locate failed
                error_msg = f"Locate operation failed: {result.result_reason}"
                if hasattr(result, 'result_message') and result.result_message:
                    error_msg += f" - {result.result_message}"

                response = {
                    "operation": "Locate",
                    "status": "error",
                    "error": error_msg
                }
        else:
            # Fallback - assume success if no status field (shouldn't happen)
            located_uids = []
            count = 0
            response = {
                "operation": "Locate",
                "status": "success",
                "located_objects": located_uids,
                "count": count
            }

        if verbose:
            if response["status"] == "success":
                print(f"Located {response['count']} objects on server")
            else:
                print("Locate operation failed")

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Locate",
            "status": "error",
            "error": str(e)
        }


def perform_revoke(proxy, verbose=False):
    """Create a symmetric key and report revoke compatibility status"""
    if verbose:
        print("Testing revoke operation compatibility...")

    try:
        # First create a symmetric key for testing
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

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "Revoke",
                "status": "error",
                "error": error_msg
            }

        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        if verbose:
            print(f"Created symmetric key with UID: {uid}")

        result = proxy.revoke(
            revocation_reason=enums.RevocationReasonCode.CESSATION_OF_OPERATION,
            uuid=uid,
            revocation_message="Testing revoke compatibility"
        )

        # Check if revoke operation succeeded
        if hasattr(result, 'result_status'):
            if result.result_status.value == enums.ResultStatus.SUCCESS:
                response = {
                    "operation": "Revoke",
                    "status": "success",
                    "uid": uid,
                    "message": "Key revoked successfully"
                }
            else:
                # Revoke failed
                error_msg = f"Revoke operation failed: {result.result_reason}"
                if hasattr(result, 'result_message') and result.result_message:
                    error_msg += f" - {result.result_message}"

                response = {
                    "operation": "Revoke",
                    "status": "error",
                    "error": error_msg
                }
        else:
            # Fallback - assume success if no status field (shouldn't happen)
            response = {
                "operation": "Revoke",
                "status": "success",
                "uid": uid,
                "message": "Key revoked successfully (result status unknown)"
            }
        if verbose:
            print(f"Revoke operation completed for UID: {uid}")

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Revoke",
            "status": "error",
            "error": str(e)
        }


def perform_discover_versions(proxy, verbose=False):
    """Discover supported KMIP versions and protocol information"""
    if verbose:
        print("Discovering supported KMIP versions...")

    try:
        # In KMIP, version discovery is typically done through:
        # 1. Initial connection negotiation (which PyKMIP handles automatically)
        # 2. Query operation for server information
        # 3. Inspecting the negotiated protocol version

        # Get server information through query operation
        try:
            query_result = proxy.query(
                query_functions=[
                    enums.QueryFunction.QUERY_SERVER_INFORMATION,
                    enums.QueryFunction.QUERY_CAPABILITIES
                ]
            )

            # Check if query succeeded
            if hasattr(query_result,
                       'result_status') and query_result.result_status.value != enums.ResultStatus.SUCCESS:
                return {
                    "operation": "DiscoverVersions",
                    "status": "error",
                    "error": f"Query failed: {query_result.result_reason}"
                }

        except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError,
                TypeError, IOError) as query_error:
            return {
                "operation": "DiscoverVersions",
                "status": "error",
                "error": f"Failed to query server information: {str(query_error)}"
            }

        # Extract version and server information
        version_info = {}

        # Get negotiated protocol version from the proxy
        if hasattr(proxy, 'protocol_version'):
            version_info['negotiated_protocol_version'] = str(
                proxy.protocol_version)
        elif hasattr(proxy, '_protocol_version'):
            # pylint: disable=protected-access
            version_info['negotiated_protocol_version'] = str(
                proxy._protocol_version)
        else:
            version_info['negotiated_protocol_version'] = "unknown"

        # Get server information if available
        server_info = {}
        if hasattr(query_result, 'server_information') and query_result.server_information:
            server_info = query_result.server_information

        # Get supported operations (indicates version capabilities)
        supported_operations = []
        if hasattr(query_result, 'operations') and query_result.operations:
            supported_operations = [op.value for op in query_result.operations]

        # Determine likely supported KMIP versions based on operations
        supported_versions = []

        # Basic KMIP 1.0 operations
        # Create, Locate, Get, GetAttributes, Destroy, Query
        basic_ops = {1, 2, 3, 4, 8, 10}
        if basic_ops.issubset(set(supported_operations)):
            supported_versions.append("1.0")

        # KMIP 1.1+ operations
        if 20 in supported_operations:  # Revoke
            supported_versions.append("1.1+")

        # KMIP 1.2+ operations
        if 32 in supported_operations:  # Encrypt
            supported_versions.append("1.2+")

        # KMIP 2.0+ operations
        advanced_ops = {29, 19, 23}  # More advanced operations
        if any(op in supported_operations for op in advanced_ops):
            supported_versions.append("2.0+")

        if verbose:
            print(
                f"Negotiated protocol version: {version_info.get('negotiated_protocol_version', 'unknown')}")
            print(f"Supported operations: {supported_operations}")
            print(f"Inferred KMIP versions: {supported_versions}")

        response = {
            "operation": "DiscoverVersions",
            "status": "success",
            "negotiated_version": version_info.get('negotiated_protocol_version', 'unknown'),
            "supported_operations": supported_operations,
            "supported_operations_count": len(supported_operations),
            "inferred_kmip_versions": supported_versions,
            "server_information": server_info,
            "version_discovery_method": "query_based_inference",
            "note": "Version discovery based on negotiated protocol and supported operations"
        }

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError,
            TypeError, IOError) as e:
        return {
            "operation": "DiscoverVersions",
            "status": "error",
            "error": str(e)
        }


def perform_encrypt(proxy, verbose=False):
    """Create a symmetric key and test encrypt operation only"""
    if verbose:
        print("Testing encrypt operation...")

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

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "Encrypt",
                "status": "error",
                "error": error_msg
            }

        uid = result.uuid if hasattr(result, 'uuid') else str(result)

        if verbose:
            print(f"Created encryption key with UID: {uid}")

        # Test data to encrypt
        test_data = b"Hello, PyKMIP Encrypt Test!"

        try:
            if verbose:
                print(f"Attempting to encrypt data: {test_data}")

            # Encrypt the data (use default parameters)
            encrypt_result = proxy.encrypt(
                data=test_data,
                unique_identifier=uid
            )

            if verbose:
                print("Data encrypted successfully")
                print(
                    f"Encrypted data length: {len(encrypt_result.get('data', b''))}")

            response = {
                "operation": "Encrypt",
                "status": "success",
                "uid": uid,
                "original_data": test_data.hex(),
                "original_data_length": len(test_data),
                "encrypted_data": encrypt_result.get('data', b'').hex(),
                "encrypted_data_length": len(encrypt_result.get('data', b'')),
                "message": "Data encrypted successfully"
            }

        except (ValueError, TypeError, AttributeError, ConnectionError, IOError) as crypto_error:
            error_msg = str(crypto_error)
            full_traceback = traceback.format_exc()

            if verbose:
                print(f"Full error traceback:\n{full_traceback}")

            # Check for known KMIP compatibility issues
            if "Invalid length used to read Base" in error_msg or "StreamNotEmptyError" in error_msg:
                response = {
                    "operation": "Encrypt",
                    "status": "error",
                    "uid": uid,
                    "error": "KMIP version compatibility issue with encrypt operation",
                    "technical_details": f"PyKMIP 1.2 parser incompatible with Cosmian KMS response format: {error_msg}",
                    "note": "Key creation succeeded, but encrypt operation has protocol parsing issues",
                    "workaround": "Use direct REST API or update PyKMIP for KMIP 2.x compatibility",
                    "full_traceback": full_traceback if verbose else None
                }
            else:
                response = {
                    "operation": "Encrypt",
                    "status": "error",
                    "uid": uid,
                    "error": error_msg,
                    "note": "Key was created successfully but encrypt operation failed",
                    "full_traceback": full_traceback if verbose else None
                }

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError, AttributeError,
            TypeError, IOError) as e:
        return {
            "operation": "Encrypt",
            "status": "error",
            "error": str(e)
        }


def perform_activate(proxy, verbose=False):
    """Create a symmetric key and test activate operation"""
    if verbose:
        print("Testing activate operation...")

    try:
        # Create a symmetric key first to have something to activate
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

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "Activate",
                "status": "error",
                "error": error_msg
            }

        # Extract UID properly - handle UniqueIdentifier objects
        if hasattr(result, 'uuid'):
            if hasattr(result.uuid, 'value'):
                uid = result.uuid.value  # Extract string from UniqueIdentifier object
            else:
                uid = str(result.uuid)
        else:
            uid = str(result)

        if verbose:
            print(f"Created key for activation with UID: {uid}")

        try:
            if verbose:
                print(f"Attempting to activate object: {uid}")

            # Activate the object
            activate_result = proxy.activate(uuid=uid)

            # Check if activate operation succeeded
            if hasattr(activate_result,
                       'result_status') and activate_result.result_status.value != enums.ResultStatus.SUCCESS:
                error_msg = f"Activate operation failed: {activate_result.result_reason}"
                if hasattr(activate_result, 'result_message') and activate_result.result_message:
                    error_msg += f" - {activate_result.result_message}"

                response = {
                    "operation": "Activate",
                    "status": "error",
                    "uid": uid,
                    "error": error_msg,
                    "note": "Key was created successfully but activate operation failed"
                }
            else:
                if verbose:
                    print("Object activated successfully")

                # Extract activated UID properly
                activated_uid = uid  # default fallback
                if hasattr(activate_result, 'uuid'):
                    if hasattr(activate_result.uuid, 'value'):
                        activated_uid = activate_result.uuid.value
                    else:
                        activated_uid = str(activate_result.uuid)

                response = {
                    "operation": "Activate",
                    "status": "success",
                    "uid": uid,
                    "message": "Object activated successfully",
                    "activated_uid": activated_uid
                }

        except (ConnectionError, TimeoutError, ValueError, KeyError,
                AttributeError, TypeError, IOError) as activate_error:
            error_msg = str(activate_error)
            full_traceback = traceback.format_exc()

            if verbose:
                print(f"Activate error traceback:\n{full_traceback}")

            response = {
                "operation": "Activate",
                "status": "error",
                "uid": uid,
                "error": error_msg,
                "note": "Key was created successfully but activate operation failed",
                "full_traceback": full_traceback if verbose else None
            }

        # Clean up the test key (best effort)

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "Activate",
            "status": "error",
            "error": str(e)
        }


def perform_mac(proxy, verbose=False):
    """Create a symmetric key and test MAC operation"""
    if verbose:
        print("Testing MAC operation...")

    try:
        # Create a symmetric key first for MAC generation
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory

        attribute_factory = AttributeFactory()

        # Create AES key first, then use it for HMAC
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr])
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "MAC",
                "status": "error",
                "error": error_msg
            }

        uid = str(result.uuid) if hasattr(result, 'uuid') else str(result)

        if verbose:
            print(f"Created MAC key with UID: {uid}")

        # Test data to generate MAC for
        test_data = b"Hello, PyKMIP MAC Test!"

        if verbose:
            print(f"Attempting to generate MAC for data: {test_data}")

        # Create cryptographic parameters for HMAC-SHA256
        crypto_params = cobjects.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )

        # Generate MAC for the data
        mac_result = proxy.mac(
            data=test_data,
            unique_identifier=uid,
            cryptographic_parameters=crypto_params
        )

        # Check if MAC operation succeeded
        if hasattr(mac_result, 'result_status') and mac_result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"MAC operation failed: {mac_result.result_reason}"
            if hasattr(mac_result, 'result_message') and mac_result.result_message:
                error_msg += f" - {mac_result.result_message}"

            return {
                "operation": "MAC",
                "status": "error",
                "uid": uid,
                "error": error_msg,
                "note": "Key was created successfully but MAC operation failed"
            }

        if verbose:
            print("MAC generated successfully")

        # Extract MAC data safely
        mac_hex = "unknown"
        mac_length = 0

        try:
            if hasattr(mac_result, 'mac_data') and mac_result.mac_data:
                if hasattr(mac_result.mac_data, 'value') and mac_result.mac_data.value:
                    mac_hex = mac_result.mac_data.value.hex()
                    mac_length = len(mac_result.mac_data.value)
        except (ValueError, AttributeError, TypeError) as extract_error:
            mac_hex = f"Error extracting MAC data: {str(extract_error)}"

        response = {
            "operation": "MAC",
            "status": "success",
            "uid": uid,
            "original_data": test_data.hex(),
            "original_data_length": len(test_data),
            "mac_data": mac_hex,
            "mac_length": mac_length,
            "message": "MAC generated successfully"
        }

        return response

    except (ConnectionError, TimeoutError, ValueError, KeyError,
            AttributeError, TypeError, IOError) as e:
        return {
            "operation": "MAC",
            "status": "error",
            "error": str(e)
        }


def perform_get(proxy, verbose=False):
    """Create a symmetric key and then retrieve it using Get operation"""
    if verbose:
        print("Testing Get operation...")

    try:
        # First create a symmetric key to retrieve
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
        usage_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT]
        )

        template = cobjects.TemplateAttribute(
            attributes=[algorithm_attr, length_attr, usage_attr])

        # Create the key
        create_result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        # Check if create operation succeeded
        if hasattr(create_result, 'result_status') and create_result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Create operation failed: {create_result.result_reason}"
            if hasattr(create_result, 'result_message') and create_result.result_message:
                error_msg += f" - {create_result.result_message}"

            return {
                "operation": "Get",
                "status": "error",
                "error": error_msg
            }

        # Extract UID properly - handle both string and object cases
        if hasattr(create_result, 'uuid'):
            if hasattr(create_result.uuid, 'value'):
                uid = create_result.uuid.value
            else:
                uid = str(create_result.uuid)
        else:
            uid = str(create_result)

        if verbose:
            print(f"Created symmetric key with UID: {uid}")

        try:
            if verbose:
                print(f"Attempting to retrieve object with UID: {uid}")

            # Get the object using the Get operation
            get_result = proxy.get(uuid=uid)

            # Check if get operation succeeded
            if hasattr(get_result, 'result_status') and get_result.result_status.value != enums.ResultStatus.SUCCESS:
                error_msg = f"Get operation failed: {get_result.result_reason}"
                if hasattr(get_result, 'result_message') and get_result.result_message:
                    error_msg += f" - {get_result.result_message}"

                return {
                    "operation": "Get",
                    "status": "error",
                    "uid": uid,
                    "error": error_msg,
                    "note": "Key was created successfully but Get operation failed"
                }

            if verbose:
                print("Object retrieved successfully")
                print(f"Get result type: {type(get_result)}")
                print(f"Get result attributes: {[attr for attr in dir(get_result) if not attr.startswith('_')]}")

            # Extract object information from the result
            object_type = "unknown"
            object_size = 0
            object_format = "unknown"

            # Get object type properly
            if hasattr(get_result, 'object_type'):
                if hasattr(get_result.object_type, 'value'):
                    object_type = get_result.object_type.value
                else:
                    object_type = str(get_result.object_type)

            # Try to extract object details from the managed object
            # The object might be directly accessible or nested
            managed_object = None
            if hasattr(get_result, 'object') and get_result.object:
                managed_object = get_result.object
            elif hasattr(get_result, 'managed_object') and get_result.managed_object:
                managed_object = get_result.managed_object
            elif hasattr(get_result, 'secret') and get_result.secret:
                # PyKMIP often returns symmetric keys as 'secret' objects
                managed_object = get_result.secret
            # Sometimes the object is the get_result itself
            elif hasattr(get_result, 'key_block'):
                managed_object = get_result

            if managed_object:
                if verbose:
                    print(f"Managed object type: {type(managed_object)}")
                    print(
                        f"Managed object attributes: {[attr for attr in dir(managed_object) if not attr.startswith('_')]}")

                # For symmetric keys, extract key block information
                key_block = None
                if hasattr(managed_object, 'key_block') and managed_object.key_block:
                    key_block = managed_object.key_block
                elif hasattr(managed_object, 'value') and hasattr(managed_object.value, 'key_block'):
                    key_block = managed_object.value.key_block

                if key_block:
                    if verbose:
                        print(f"Key block type: {type(key_block)}")
                        print(f"Key block attributes: {[attr for attr in dir(key_block) if not attr.startswith('_')]}")

                    # Extract key format type
                    if hasattr(key_block, 'key_format_type') and key_block.key_format_type:
                        if hasattr(key_block.key_format_type, 'value'):
                            format_enum = key_block.key_format_type.value
                            # Convert enum to string for JSON serialization
                            if hasattr(format_enum, 'name'):
                                object_format = format_enum.name
                            elif hasattr(format_enum, 'value'):
                                object_format = str(format_enum.value)
                            else:
                                object_format = str(format_enum)
                            if verbose:
                                print(f"Key format type from .value: {object_format}")
                        else:
                            object_format = str(key_block.key_format_type)
                            if verbose:
                                print(f"Key format type from str(): {object_format}")
                    elif verbose:
                        print("No key_format_type found in key_block")

                    # Extract key material and size
                    if hasattr(key_block, 'key_value') and key_block.key_value:
                        key_value = key_block.key_value

                        if verbose:
                            print(f"Key value type: {type(key_value)}")
                            print(
                                f"Key value attributes: {[attr for attr in dir(key_value) if not attr.startswith('_')]}")

                        # Try different possible attribute names for key material
                        key_material = None
                        if hasattr(key_value, 'key_material') and key_value.key_material:
                            key_material_obj = key_value.key_material
                            if verbose:
                                print(f"Key material object type: {type(key_material_obj)}")
                                print(
                                    f"Key material object attributes: {[attr for attr in dir(key_material_obj) if not attr.startswith('_')]}")

                            # Extract the actual bytes from the key material object
                            if hasattr(key_material_obj, 'value'):
                                key_material = key_material_obj.value
                            elif hasattr(key_material_obj, 'data'):
                                key_material = key_material_obj.data
                            else:
                                key_material = key_material_obj

                        elif hasattr(key_value, 'material') and key_value.material:
                            key_material_obj = key_value.material
                            if hasattr(key_material_obj, 'value'):
                                key_material = key_material_obj.value
                            else:
                                key_material = key_material_obj
                        elif hasattr(key_value, 'value') and key_value.value:
                            # Sometimes the key material is directly in value
                            key_material = key_value.value

                        # Calculate size if we found key material
                        if key_material:
                            if isinstance(key_material, (bytes, bytearray)):
                                object_size = len(key_material)
                            elif isinstance(key_material, str):
                                # Handle hex-encoded strings
                                try:
                                    object_size = len(bytes.fromhex(key_material))
                                except ValueError:
                                    object_size = len(key_material.encode('utf-8'))
                            else:
                                # Try to get length of the object
                                try:
                                    object_size = len(key_material)
                                except (TypeError, AttributeError):
                                    object_size = 0

                            if verbose:
                                print(f"Key material type: {type(key_material)}")
                                print(f"Key material size: {object_size} bytes")
                        elif verbose:
                            print("No key material found in key_value")
                    elif verbose:
                        print("No key_value found in key_block")
                elif verbose:
                    print("No key_block found in managed_object")
            elif verbose:
                print("No managed object found in get_result")

            # Extract returned UID
            returned_uid = uid  # fallback
            if hasattr(get_result, 'uuid'):
                if hasattr(get_result.uuid, 'value'):
                    returned_uid = get_result.uuid.value
                else:
                    returned_uid = str(get_result.uuid)

            response = {
                "operation": "Get",
                "status": "success",
                "uid": uid,
                "returned_uid": returned_uid,
                "object_type": object_type,
                "object_format": object_format,
                "key_size_bytes": object_size,
                "message": "Object retrieved successfully"
            }

            return response

        except Exception as get_error:
            error_msg = str(get_error)
            full_traceback = traceback.format_exc()

            if verbose:
                print(f"Get error traceback:\n{full_traceback}")

            return {
                "operation": "Get",
                "status": "error",
                "uid": uid,
                "error": error_msg,
                "exception_type": type(get_error).__name__,
                "note": "Key was created successfully but Get operation failed",
                "full_traceback": full_traceback if verbose else None
            }

    except Exception as e:
        error_msg = str(e)
        full_traceback = traceback.format_exc()

        return {
            "operation": "Get",
            "status": "error",
            "error": error_msg,
            "exception_type": type(e).__name__,
            "full_traceback": full_traceback if verbose else None
        }


if __name__ == "__main__":
    main()
