#!/usr/bin/env python3
"""
PyKMIP Certify Operation Implementation

This module contains the perform_certify function that implements
the KMIP Certify operation testing functionality.
"""

from kmip.core import enums


def perform_certify(proxy, verbose=False):
    """Test KMIP Certify operation (simulated via key pair creation and signing)

    Since PyKMIP doesn't implement the CERTIFY operation directly, this function
    simulates what a certify operation would do by:
    1. Creating a key pair (as certification typically involves public keys)
    2. Attempting to sign data (as signing is part of certification workflows)
    3. Reporting the results

    Args:
        proxy: KMIP proxy connection
        verbose: Enable verbose output

    Returns:
        dict: Operation result with status and details
    """
    if verbose:
        print("Testing KMIP Certify operation (simulated)...")

    try:
        # Import necessary classes for key pair creation
        from kmip.core import objects as cobjects
        from kmip.core.factories.attributes import AttributeFactory

        # Create attribute factory
        attribute_factory = AttributeFactory()

        if verbose:
            print("Creating RSA key pair for certification simulation...")

        # Create template attributes for RSA key pair
        algorithm_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.RSA
        )
        length_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            2048
        )
        usage_attr = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.SIGN, enums.CryptographicUsageMask.VERIFY]
        )

        # Create common template for key pair creation
        common_template = cobjects.CommonTemplateAttribute(
            attributes=[algorithm_attr, length_attr, usage_attr])

        # Create the key pair
        result = proxy.create_key_pair(
            common_template_attribute=common_template)

        # Check if create operation succeeded
        if hasattr(result, 'result_status') and result.result_status.value != enums.ResultStatus.SUCCESS:
            error_msg = f"Key pair creation failed: {result.result_reason}"
            if hasattr(result, 'result_message') and result.result_message:
                error_msg += f" - {result.result_message}"

            return {
                "operation": "Certify",
                "status": "error",
                "error": error_msg,
                "note": "KMIP CERTIFY operation not directly supported by PyKMIP"
            }

        # Extract key pair UIDs
        private_key_uid = str(result.private_key_uuid) if hasattr(
            result, 'private_key_uuid') else None
        public_key_uid = str(result.public_key_uuid) if hasattr(
            result, 'public_key_uuid') else None

        if verbose:
            print(
                f"Created key pair - Private: {private_key_uid}, Public: {public_key_uid}")

        # Simulate certification by attempting to sign test data
        test_data = b"Certificate test data for KMIP Certify operation"

        try:
            if verbose:
                print("Attempting to sign data (certification simulation)...")

            # Create cryptographic parameters for signing
            crypto_params = cobjects.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
            )

            # Sign the data using the private key
            sign_result = proxy.sign(
                data=test_data,
                unique_identifier=private_key_uid,
                cryptographic_parameters=crypto_params
            )

            # Check if signing succeeded (handle both dict and object results)
            if isinstance(sign_result, dict):
                result_status = sign_result.get('result_status')
                result_reason = sign_result.get('result_reason')
                result_message = sign_result.get('result_message')
                signature_data = sign_result.get('signature')
            else:
                result_status = getattr(sign_result, 'result_status', None)
                result_reason = getattr(sign_result, 'result_reason', None)
                result_message = getattr(sign_result, 'result_message', None)
                signature_data = getattr(sign_result, 'signature', None)

            if result_status and result_status.value != enums.ResultStatus.SUCCESS:
                error_msg = f"Signing failed: {result_reason}"
                if result_message:
                    error_msg += f" - {result_message}"

                # Check if it's an unsupported operation
                if "unsupported KMIP 1 operation: Sign" in str(result_message):
                    response = {
                        "operation": "Certify",
                        "status": "error",
                        "private_key_uid": private_key_uid,
                        "public_key_uid": public_key_uid,
                        "error": "KMIP Sign operation not supported by server",
                        "technical_details": f"Cosmian KMS KMIP 1.x mode: {result_message}",
                        "note": "Key pair created successfully but Sign operation is not supported in KMIP 1.x",
                        "workaround": "Use direct REST API or configure server for KMIP 2.x mode"
                    }
                else:
                    response = {
                        "operation": "Certify",
                        "status": "error",
                        "private_key_uid": private_key_uid,
                        "public_key_uid": public_key_uid,
                        "error": error_msg,
                        "note": "Key pair created successfully but signing failed"
                    }
            else:
                if verbose:
                    print("Signing successful - certification simulation completed")

                # Extract signature data safely
                signature_hex = "No signature data"
                signature_length = 0

                if signature_data:
                    if isinstance(signature_data, bytes):
                        signature_hex = signature_data.hex()
                        signature_length = len(signature_data)
                    else:
                        signature_hex = str(signature_data)
                        signature_length = len(str(signature_data))

                response = {
                    "operation": "Certify",
                    "status": "success",
                    "private_key_uid": private_key_uid,
                    "public_key_uid": public_key_uid,
                    "test_data": test_data.hex(),
                    "signature": signature_hex,
                    "signature_length": signature_length,
                    "message": "Certification simulation completed successfully",
                    "note": "KMIP CERTIFY operation simulated via key pair creation and signing"
                }

        except Exception as sign_error:
            import traceback
            error_msg = str(sign_error)
            full_traceback = traceback.format_exc()

            if verbose:
                print(f"Signing error traceback:\n{full_traceback}")

            # Check for known KMIP compatibility issues
            if "Invalid length used to read Base" in error_msg or "StreamNotEmptyError" in error_msg:
                response = {
                    "operation": "Certify",
                    "status": "error",
                    "private_key_uid": private_key_uid,
                    "public_key_uid": public_key_uid,
                    "error": "KMIP version compatibility issue with signing operation",
                    "technical_details": f"PyKMIP 1.2 parser incompatible with Cosmian KMS response format: {error_msg}",
                    "note": "Key pair creation succeeded, but signing has protocol parsing issues",
                    "workaround": "Use direct REST API or update PyKMIP for KMIP 2.x compatibility",
                    "full_traceback": full_traceback if verbose else None
                }
            else:
                response = {
                    "operation": "Certify",
                    "status": "error",
                    "private_key_uid": private_key_uid,
                    "public_key_uid": public_key_uid,
                    "error": error_msg,
                    "note": "Key pair created successfully but signing operation failed",
                    "full_traceback": full_traceback if verbose else None
                }

        # Clean up the test keys (best effort)
        try:
            if verbose:
                print(f"Cleaning up test keys...")
            if private_key_uid:
                proxy.destroy(uuid=private_key_uid)
            if public_key_uid:
                proxy.destroy(uuid=public_key_uid)
        except:
            if verbose:
                print("Note: Could not clean up test keys")

        return response

    except Exception as e:
        return {
            "operation": "Certify",
            "status": "error",
            "error": str(e),
            "note": "KMIP CERTIFY operation not directly supported by PyKMIP - simulated via key pair creation"
        }
