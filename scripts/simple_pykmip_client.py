#!/usr/bin/env python3
"""
Simple PyKMIP Client for testing basic operations against Cosmian KMS server.
Uses the ProxyKmipClient (pie client) which is simpler than KMIPProxy.
"""

import sys
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums

def test_basic_operations():
    """Test basic PyKMIP operations against Cosmian KMS server."""
    print("=== Simple PyKMIP Test ===")
    
    # Create client with basic configuration
    client = ProxyKmipClient(
        hostname='127.0.0.1',
        port=9998,  # Cosmian KMS socket server port
        username='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',  # JWT token
        password=None
    )
    
    try:
        print("1. Opening connection...")
        client.open()
        print("   ✓ Connected successfully")
        
        print("\n2. Testing create operation...")
        # Create a symmetric key using the simple API
        uid = client.create(
            enums.CryptographicAlgorithm.AES,
            256
        )
        print(f"   ✓ Created key with UID: {uid}")
        
        print("\n3. Testing get operation...")
        # Get the key we just created
        key_object = client.get(uid)
        print(f"   ✓ Retrieved key object")
        
        print("\n4. Testing destroy operation...")
        # Clean up - destroy the test key
        client.destroy(uid)
        print(f"   ✓ Destroyed key: {uid}")
        
        print("\n✅ All basic operations completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False
        
    finally:
        try:
            client.close()
            print("\n5. Connection closed")
        except:
            pass

if __name__ == "__main__":
    success = test_basic_operations()
    sys.exit(0 if success else 1)
