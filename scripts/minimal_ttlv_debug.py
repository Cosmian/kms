#!/usr/bin/env python3
"""
Minimal TTLV Debug - Capture the exact parsing failure point
"""

import sys
import logging
import socket
from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums

# Set up detailed logging to see exactly where parsing fails
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s:%(name)s:%(message)s'
)

class DeepDebugProxy(KMIPProxy):
    """Proxy that adds extra debugging to pinpoint parsing failure"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def _build_request_message(self, request):
        """Override to add debug info"""
        print("🔍 Building request message...")
        result = super()._build_request_message(request)
        print(f"🔍 Request message built successfully")
        return result
    
    def _send_request(self, request):
        """Override to add debug info"""
        print("🔍 Sending request...")
        try:
            result = super()._send_request(request)
            print("🔍 Request sent and response received successfully")
            return result
        except Exception as e:
            print(f"❌ Request/response failed: {e}")
            print(f"   Error type: {type(e).__name__}")
            
            # Check if it's a parsing error
            if "expected 9, received 3" in str(e):
                print("🔍 This is the TTLV parsing error!")
                print("   PyKMIP expected Structure (9) but got BigInteger (3)")
                print("   This suggests the server response format is incompatible")
            
            raise

def test_discover_versions_with_debug():
    """Test discover_versions with maximum debugging"""
    
    print("=== DISCOVER VERSIONS DEBUG TEST ===")
    
    try:
        # Create proxy with debug logging
        proxy = DeepDebugProxy(config_file='scripts/pykmip.conf')
        
        print("🔍 Opening connection...")
        proxy.open()
        print("✅ Connection opened successfully")
        
        print("🔍 Calling discover_versions...")
        supported_versions = proxy.discover_versions()
        print("✅ discover_versions succeeded!")
        print(f"   Supported versions: {[str(v) for v in supported_versions]}")
        
        proxy.close()
        
    except Exception as e:
        print(f"❌ discover_versions failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        
        # Analyze the error
        error_str = str(e)
        if "expected 9, received 3" in error_str:
            print("\n🔍 ANALYSIS:")
            print("   - The SSL connection is working (no SSL errors)")
            print("   - The request is being sent successfully")
            print("   - The server is responding")
            print("   - BUT: The response TTLV format is incompatible")
            print("   - Server sends BigInteger (3) where PyKMIP expects Structure (9)")
            print("\n💡 LIKELY CAUSES:")
            print("   1. KMIP version mismatch (server uses different KMIP version)")
            print("   2. Custom TTLV encoding in Cosmian KMS")
            print("   3. Non-standard KMIP response format")
            print("   4. Server implementation differs from KMIP spec")
        
        # Try to get more info about the connection state
        if 'proxy' in locals() and hasattr(proxy, 'socket'):
            try:
                print(f"\n🔍 Connection state: {proxy.socket}")
            except:
                pass
        
        import traceback
        print("\n🔍 Full traceback:")
        traceback.print_exc()
        
        if 'proxy' in locals():
            try:
                proxy.close()
            except:
                pass

def test_with_different_kmip_versions():
    """Test discover_versions with different KMIP versions"""
    
    versions_to_test = [
        enums.KMIPVersion.KMIP_1_0,
        enums.KMIPVersion.KMIP_1_1,
        enums.KMIPVersion.KMIP_1_2,
    ]
    
    for version in versions_to_test:
        print(f"\n=== TESTING WITH KMIP {version.value} ===")
        
        try:
            proxy = DeepDebugProxy(
                config_file='scripts/pykmip.conf',
                kmip_version=version
            )
            
            proxy.open()
            print(f"✅ Connection opened with KMIP {version.value}")
            
            supported_versions = proxy.discover_versions()
            print(f"✅ discover_versions succeeded with KMIP {version.value}!")
            print(f"   Server supports: {[str(v) for v in supported_versions]}")
            
            proxy.close()
            return version  # Found working version
            
        except Exception as e:
            print(f"❌ KMIP {version.value} failed: {e}")
            if 'proxy' in locals():
                try:
                    proxy.close()
                except:
                    pass
    
    return None

if __name__ == "__main__":
    print("=== DEEP TTLV PARSING DEBUG ===")
    
    # First test with default settings
    test_discover_versions_with_debug()
    
    print("\n" + "="*50)
    
    # Then test with different KMIP versions
    working_version = test_with_different_kmip_versions()
    
    if working_version:
        print(f"\n✅ SUCCESS: KMIP {working_version.value} works!")
    else:
        print("\n❌ FAILURE: No KMIP version works")
        print("\nThis confirms the issue is a fundamental TTLV encoding incompatibility")
        print("between PyKMIP and Cosmian KMS server.")
