#!/usr/bin/env python3
"""
Simple PyKMIP debug script to test KMIP compatibility with Cosmian KMS server.
Tests discover_versions and query operations to verify TTLV parsing is working.
"""

import sys
import traceback
from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums

def test_kmip_operations():
    """Test basic KMIP operations against Cosmian KMS server."""
    print("=== PyKMIP Simple Debug Test ===")
    
    # Create KMIP client using KMIPProxy which has discover_versions and query
    client = KMIPProxy(
        config_file="scripts/pykmip.conf"  # Use config file for all connection settings
    )
    
    try:
        print("1. Opening connection to Cosmian KMS server...")
        client.open()
        print("   ✓ Connection opened successfully")
        
        print("\n2. Testing discover_versions operation...")
        result = client.discover_versions()
        print("   ✓ discover_versions succeeded")
        
        # Handle the result properly
        if hasattr(result, 'supported_versions') and result.supported_versions:
            supported_versions = [str(v) for v in result.supported_versions]
            print(f"   Supported KMIP versions: {', '.join(supported_versions)}")
        elif hasattr(result, 'protocol_versions') and result.protocol_versions:
            supported_versions = [str(v) for v in result.protocol_versions]
            print(f"   Supported KMIP versions: {', '.join(supported_versions)}")
        else:
            print("   Warning: No protocol versions returned")
            
        print("\n3. Testing query operation...")
        # Query requires query_functions parameter
        result = client.query(
            query_functions=[
                enums.QueryFunction.QUERY_OBJECTS,
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_SERVER_INFORMATION
            ]
        )
        print("   ✓ query operation succeeded")
        
        if hasattr(result, 'server_information'):
            print(f"   Server information: {result.server_information}")
        if hasattr(result, 'operations'):
            operations = [str(op) for op in result.operations or []]
            print(f"   Supported operations: {', '.join(operations[:5])}{'...' if len(operations) > 5 else ''}")
            
        print("\n4. Testing basic create operation...")
        # Test a simple create to verify TTLV parsing works
        # KMIPProxy.create() requires ObjectType as first parameter
        from kmip.core import objects
        from kmip.core.factories.attributes import AttributeFactory
        
        # Use attribute factory to properly create attributes
        attribute_factory = AttributeFactory()
        
        # Create template attribute with algorithm and length
        algorithm_attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        length_attribute = attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            256
        )
        
        template = objects.TemplateAttribute(
            attributes=[algorithm_attribute, length_attribute]
        )
        
        uid = client.create(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=template
        )
        
        # Extract UID from result object
        if hasattr(uid, 'uuid'):
            actual_uid = uid.uuid
        else:
            actual_uid = str(uid)
            
        print(f"   ✓ Created AES key with UID: {actual_uid}")
        
        print("\n✅ All tests passed! PyKMIP integration is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Error occurred: {e}")
        print(f"Error type: {type(e).__name__}")
        traceback.print_exc()
        return False
        
    finally:
        try:
            client.close()
            print("\n5. Connection closed")
        except:
            pass
            
    return True

if __name__ == "__main__":
    success = test_kmip_operations()
    sys.exit(0 if success else 1)
