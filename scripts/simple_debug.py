#!/usr/bin/env python3
"""
Simple KMIP Debug - Test different KMIP versions and operations
"""

import sys
import logging
from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('kmip')

def test_kmip_versions():
    """Test different KMIP versions to find compatibility"""
    
    versions_to_test = [
        enums.KMIPVersion.KMIP_1_0,
        enums.KMIPVersion.KMIP_1_1, 
        enums.KMIPVersion.KMIP_1_2,
        enums.KMIPVersion.KMIP_2_0
    ]
    
    for version in versions_to_test:
        print(f"\n=== Testing KMIP Version {version.value} ===")
        
        try:
            proxy = KMIPProxy(
                config_file='scripts/pykmip.conf',
                kmip_version=version
            )
            
            proxy.open()
            
            # Try discover_versions first (most basic operation)
            print("Trying discover_versions...")
            supported_versions = proxy.discover_versions()
            print(f"✅ discover_versions succeeded: {[v.value for v in supported_versions]}")
            
            # If discover_versions works, try query
            print("Trying query...")
            result = proxy.query(query_functions=[enums.QueryFunction.QUERY_OPERATIONS])
            print(f"✅ query succeeded: {[op.value for op in result.operations]}")
            
            proxy.close()
            print(f"✅ KMIP Version {version.value} is compatible!")
            return version
            
        except Exception as e:
            print(f"❌ KMIP Version {version.value} failed: {e}")
            if 'proxy' in locals():
                try:
                    proxy.close()
                except:
                    pass
    
    return None

def test_minimal_operations():
    """Test the most basic KMIP operations"""
    
    operations_to_test = [
        ("discover_versions", lambda p: p.discover_versions()),
        ("query_operations", lambda p: p.query(query_functions=[enums.QueryFunction.QUERY_OPERATIONS])),
        ("query_server_info", lambda p: p.query(query_functions=[enums.QueryFunction.QUERY_SERVER_INFORMATION])),
        ("query_all", lambda p: p.query()),
    ]
    
    for op_name, op_func in operations_to_test:
        print(f"\n=== Testing {op_name} ===")
        
        try:
            proxy = KMIPProxy(config_file='scripts/pykmip.conf')
            proxy.open()
            
            result = op_func(proxy)
            print(f"✅ {op_name} succeeded!")
            
            if hasattr(result, 'operations'):
                print(f"  Operations: {[op.value for op in result.operations]}")
            if hasattr(result, 'server_information'):
                print(f"  Server Info: {result.server_information}")
            
            proxy.close()
            
        except Exception as e:
            print(f"❌ {op_name} failed: {e}")
            if 'Expected 9, received 3' in str(e):
                print("  🔍 This is the TTLV parsing error we're investigating")
            if 'proxy' in locals():
                try:
                    proxy.close()
                except:
                    pass

if __name__ == "__main__":
    print("=== KMIP Compatibility Debug Tool ===")
    
    print("\n1. Testing KMIP version compatibility...")
    compatible_version = test_kmip_versions()
    
    print("\n2. Testing minimal operations...")  
    test_minimal_operations()
    
    if compatible_version:
        print(f"\n✅ Found compatible KMIP version: {compatible_version.value}")
    else:
        print("\n❌ No compatible KMIP version found")
        print("\nThis suggests the issue is either:")
        print("  1. Fundamental TTLV encoding difference")
        print("  2. Server implementation incompatibility") 
        print("  3. Certificate/SSL handshake issue affecting message parsing")
