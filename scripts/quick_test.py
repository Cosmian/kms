#!/usr/bin/env python3
"""
Quick test to verify PyKMIP operations and their status reporting
"""

import subprocess
import json
import sys
import os

def test_operation(operation):
    """Test a single PyKMIP operation"""
    print(f"\n🧪 Testing {operation} operation...")
    print("=" * 50)
    
    cmd = [
        sys.executable, 
        "scripts/pykmip_client.py",
        "--configuration", "scripts/pykmip.conf",
        "--operation", operation
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd="/Users/bgrieder/projects/kms")
        
        print(f"Exit Code: {result.returncode}")
        print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        
        # Try to parse JSON
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout.strip())
                status = data.get('status', 'unknown')
                print(f"📊 Status: {status}")
                
                if status == 'error':
                    print(f"❌ ERROR: {data.get('error', 'No error message')}")
                    return False
                elif status == 'success':
                    print("✅ SUCCESS")
                    return True
                else:
                    print(f"⚠️  UNKNOWN STATUS: {status}")
                    return False
                    
            except json.JSONDecodeError as e:
                print(f"❌ JSON Parse Error: {e}")
                return False
        else:
            print("❌ No output received")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Operation timed out")
        return False
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

def main():
    print("🔍 PyKMIP Operations Status Test")
    print("=" * 60)
    
    # Change to project directory
    os.chdir("/Users/bgrieder/projects/kms")
    
    operations = [
        "query",
        "create", 
        "revoke",
        "destroy",
        "encrypt_decrypt"
    ]
    
    results = {}
    
    for op in operations:
        results[op] = test_operation(op)
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    
    successful = [op for op, success in results.items() if success]
    failed = [op for op, success in results.items() if not success]
    
    print(f"✅ Successful ({len(successful)}): {', '.join(successful)}")
    print(f"❌ Failed ({len(failed)}): {', '.join(failed)}")
    
    print(f"\nSuccess Rate: {len(successful)}/{len(operations)} ({len(successful)/len(operations)*100:.1f}%)")
    
    return len(failed) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
