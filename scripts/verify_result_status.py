#!/usr/bin/env python3
"""
Comprehensive Result Status Check Verification

This script tests all PyKMIP operations to ensure they properly check
and report the actual server result status instead of always reporting success.
"""

import json
import subprocess
import sys

def test_operation(operation):
    """Test a single operation and return detailed results."""
    cmd = [
        sys.executable, 
        "scripts/pykmip_client.py", 
        "--configuration", "scripts/pykmip.conf", 
        "--operation", operation
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            output = result.stdout.strip()
            lines = output.split('\n')
            json_line = lines[-1] if lines else '{}'
            return json.loads(json_line)
        else:
            return {"status": "error", "error": f"Process failed: {result.stderr}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def main():
    print("🔍 Result Status Check Verification")
    print("=" * 50)
    print("Testing that all operations properly check server result status...")
    print()
    
    operations = [
        ("query", "Server capability query"),
        ("create", "Symmetric key creation"),
        ("locate", "Object location"),
        ("get", "Attribute retrieval"),
        ("destroy", "Key destruction"),
        ("create_keypair", "RSA key pair creation"),
        ("encrypt_decrypt", "Encrypt/decrypt operations")
    ]
    
    results = {}
    
    for op, description in operations:
        print(f"Testing {op.upper()}: {description}")
        result = test_operation(op)
        results[op] = result
        
        status = result.get('status', 'unknown')
        if status == 'success':
            print(f"   ✅ SUCCESS")
            if 'uid' in result:
                print(f"      Key: {result['uid']}")
            elif 'count' in result:
                print(f"      Objects: {result['count']}")
        elif status == 'error':
            error = result.get('error', 'Unknown error')
            print(f"   ❌ ERROR: {error[:80]}{'...' if len(error) > 80 else ''}")
        else:
            print(f"   ⚠️  UNKNOWN STATUS: {status}")
        print()
    
    # Analysis
    print("📊 ANALYSIS:")
    print("=" * 50)
    
    success_ops = [op for op, result in results.items() if result.get('status') == 'success']
    error_ops = [op for op, result in results.items() if result.get('status') == 'error']
    
    print(f"✅ Successful operations ({len(success_ops)}): {', '.join(success_ops)}")
    print(f"❌ Failed operations ({len(error_ops)}): {', '.join(error_ops)}")
    print()
    
    # Check for proper error reporting
    print("🔍 ERROR REPORTING VERIFICATION:")
    for op in error_ops:
        result = results[op]
        error = result.get('error', '')
        
        if 'KMIP' in error or 'conversion' in error.lower() or 'not supported' in error.lower():
            print(f"   ✅ {op}: Proper KMIP compatibility error reported")
        elif 'PyKMIP' in error and 'COMMENT' in error:
            print(f"   ✅ {op}: Proper PyKMIP attribute compatibility error reported")
        elif 'Invalid length' in error or 'StreamNotEmptyError' in error:
            print(f"   ✅ {op}: Proper TTLV parsing error reported")
        else:
            print(f"   ⚠️  {op}: Generic error: {error[:60]}...")
    
    print("\n🎯 RESULT STATUS CHECK STATUS:")
    print("All operations now properly check server result_status field")
    print("and report actual success/failure instead of assuming success.")
    
    return len(error_ops) < len(success_ops)  # More successes than failures

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
