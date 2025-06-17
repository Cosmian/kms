#!/usr/bin/env python3
"""
Debug version of MAC operation to find where it hangs
"""

import sys
import json
sys.path.insert(0, '/Users/bgrieder/projects/kms')

from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums, objects as cobjects
from kmip.core.factories.attributes import AttributeFactory

def debug_mac_operation():
    try:
        print("1. Starting MAC operation debug...")
        
        proxy = KMIPProxy(config_file='scripts/pykmip.conf')
        print("2. Created proxy")
        
        proxy.open()
        print("3. Opened proxy connection")
        
        # Create a symmetric key first
        print("4. Creating symmetric key...")
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
        print("5. Created template")
        
        result = proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)
        print("6. Created key")
        
        uid = str(result.uuid)
        print(f"7. Got UID: {uid}")
        
        # Test data to MAC
        test_data = b"Hello, PyKMIP MAC Test!"
        print(f"8. Test data: {test_data}")
        
        # Create cryptographic parameters
        print("9. Creating crypto parameters...")
        crypto_params = cobjects.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        print("10. Created crypto parameters")
        
        # Generate MAC
        print("11. Calling MAC operation...")
        mac_result = proxy.mac(
            data=test_data,
            unique_identifier=uid,
            cryptographic_parameters=crypto_params
        )
        print("12. MAC operation completed!")
        
        print(f"13. MAC result type: {type(mac_result)}")
        if hasattr(mac_result, 'result_status'):
            print(f"14. Status: {mac_result.result_status}")
        
        # Get the MAC value
        if hasattr(mac_result, 'mac_data') and mac_result.mac_data:
            mac_value = mac_result.mac_data.value
            print(f"15. MAC value: {mac_value.hex() if mac_value else 'None'}")
        else:
            mac_value = None
            print("15. No MAC data found")
        
        response = {
            "operation": "MAC",
            "status": "success",
            "uid": uid,
            "test_data": test_data.hex(),
            "mac_value": mac_value.hex() if mac_value else None
        }
        
        print("16. Cleaning up...")
        proxy.destroy(uuid=uid)
        proxy.close()
        print("17. Done!")
        
        return response
        
    except Exception as e:
        print(f"Error at step: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    result = debug_mac_operation()
    print(json.dumps(result, indent=2))
