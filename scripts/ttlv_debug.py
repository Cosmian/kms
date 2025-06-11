#!/usr/bin/env python3
"""
TTLV Debug Script - Captures raw KMIP messages for analysis
"""

import argparse
import sys
import socket
import ssl
import binascii
import struct
from io import BytesIO
from kmip.services.kmip_client import KMIPProxy
from kmip.core import enums

class TTLVDebugProxy(KMIPProxy):
    """Debug version of KMIPProxy that captures raw TTLV data"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raw_request = None
        self.raw_response = None
    
    def _send_request(self, request):
        """Override to capture raw TTLV data before and after transmission"""
        try:
            # Serialize the request to TTLV
            request_stream = BytesIO()
            request.write(request_stream)
            self.raw_request = request_stream.getvalue()
            
            print(f"=== RAW REQUEST TTLV ({len(self.raw_request)} bytes) ===")
            self._print_hex_dump(self.raw_request)
            self._analyze_ttlv_structure(self.raw_request, "REQUEST")
            print()
            
            # Send the request
            self.socket.send(self.raw_request)
            
            # Read the response in chunks to better understand structure
            print("=== READING RESPONSE ===")
            
            # Read TTLV header first (8 bytes: 3 tag + 1 type + 4 length)
            header = self._recv_exact(8)
            if len(header) < 8:
                raise Exception("Incomplete TTLV header received")
            
            # Parse header
            tag = int.from_bytes(header[0:3], 'big')
            ttlv_type = header[3]
            length = int.from_bytes(header[4:8], 'big')
            
            print(f"Response Header:")
            print(f"  Tag: 0x{tag:06X} ({self._tag_name(tag)})")
            print(f"  Type: {ttlv_type} ({self._type_name(ttlv_type)})")
            print(f"  Length: {length}")
            
            # This is where the error occurs - PyKMIP expects type 9 (Structure) but gets type 3 (BigInteger)
            if ttlv_type == 3:
                print(f"  ⚠️  WARNING: Received BigInteger (3) instead of expected Structure (9)")
                print(f"      This is likely the cause of the parsing error!")
            
            # Read the rest of the message
            remaining = self._recv_exact(length)
            self.raw_response = header + remaining
            
            print(f"\n=== RAW RESPONSE TTLV ({len(self.raw_response)} bytes) ===")
            self._print_hex_dump(self.raw_response)
            self._analyze_ttlv_structure(self.raw_response, "RESPONSE")
            print()
            
            # Try to parse the response with PyKMIP
            response_stream = BytesIO(self.raw_response)
            response = ResponseMessage()
            response.read(response_stream)
            
            return response
            
        except Exception as e:
            print(f"TTLV Debug Error: {e}")
            if hasattr(self, 'raw_response') and self.raw_response:
                print(f"Raw response hex: {binascii.hexlify(self.raw_response).decode()}")
            raise
    
    def _recv_exact(self, num_bytes):
        """Receive exactly num_bytes from socket"""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                break
            data += chunk
        return data
    
    def _print_hex_dump(self, data):
        """Print hex dump of binary data"""
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"{i:08x}: {hex_str:<48} |{ascii_str}|")
    
    def _analyze_ttlv_structure(self, data, label):
        """Analyze TTLV structure recursively"""
        print(f"\n=== {label} TTLV STRUCTURE ANALYSIS ===")
        self._parse_ttlv_recursive(data, 0, 0)
    
    def _parse_ttlv_recursive(self, data, offset, depth):
        """Recursively parse TTLV structure"""
        indent = "  " * depth
        
        while offset < len(data):
            if offset + 8 > len(data):
                print(f"{indent}[Truncated - insufficient data for header]")
                break
                
            # Parse TTLV header
            tag = int.from_bytes(data[offset:offset+3], 'big')
            ttlv_type = data[offset+3]
            length = int.from_bytes(data[offset+4:offset+8], 'big')
            
            print(f"{indent}Tag: 0x{tag:06X} ({self._tag_name(tag)})")
            print(f"{indent}Type: {ttlv_type} ({self._type_name(ttlv_type)})")
            print(f"{indent}Length: {length}")
            
            # Calculate padded length (TTLV uses 8-byte alignment)
            padded_length = ((length + 7) // 8) * 8
            
            if offset + 8 + padded_length > len(data):
                print(f"{indent}[Truncated - insufficient data for value]")
                break
            
            value_data = data[offset+8:offset+8+length]
            
            if ttlv_type == 1:  # Structure
                print(f"{indent}Value: <Structure with {length} bytes>")
                if length > 0:
                    self._parse_ttlv_recursive(value_data, 0, depth + 1)
            elif ttlv_type == 2:  # Integer  
                if length == 4:
                    val = struct.unpack('>I', value_data)[0]
                    print(f"{indent}Value: {val}")
                elif length == 8:
                    val = struct.unpack('>Q', value_data)[0] 
                    print(f"{indent}Value: {val}")
                else:
                    print(f"{indent}Value: <{length} byte integer>")
            elif ttlv_type == 3:  # LongInteger/BigInteger
                print(f"{indent}Value: <{length} byte big integer>")
                if length <= 8:
                    # Try to interpret as integer
                    padded_val = value_data.ljust(8, b'\x00')
                    val = struct.unpack('>Q', padded_val)[0]
                    print(f"{indent}  Interpreted as: {val}")
            elif ttlv_type == 7:  # TextString
                try:
                    text = value_data.decode('utf-8')
                    print(f"{indent}Value: '{text}'")
                except:
                    print(f"{indent}Value: <{length} byte text, invalid UTF-8>")
            elif ttlv_type == 5:  # Enumeration
                if length == 4:
                    val = struct.unpack('>I', value_data)[0]
                    print(f"{indent}Value: {val} (enum)")
                else:
                    print(f"{indent}Value: <{length} byte enumeration>")
            else:
                print(f"{indent}Value: <{length} bytes of type {ttlv_type}>")
            
            offset += 8 + padded_length
            
            if depth == 0:  # Only process one top-level item for now
                break
    
    def _tag_name(self, tag):
        """Get human-readable tag name"""
        tag_names = {
            0x420008: "Request Message",
            0x42007B: "Response Message", 
            0x42007C: "Batch Header",
            0x42007A: "Batch Count",
            0x420078: "Batch Item",
            0x42005C: "Operation",
            0x420079: "Result Status",
            0x42007D: "Result Reason", 
            0x42007E: "Result Message",
            0x420025: "Query",
            0x420020: "Query Function",
            0x42001C: "Operations",
        }
        return tag_names.get(tag, "Unknown")
    
    def _type_name(self, ttlv_type):
        """Get human-readable type name"""
        type_names = {
            1: "Structure",
            2: "Integer", 
            3: "LongInteger",
            4: "BigInteger",
            5: "Enumeration",
            6: "Boolean",
            7: "TextString",
            8: "ByteString",
            9: "DateTime",
            10: "Interval"
        }
        return type_names.get(ttlv_type, f"Unknown({ttlv_type})")

def main():
    parser = argparse.ArgumentParser(description='TTLV Debug Tool')
    parser.add_argument('--configuration', default='scripts/pykmip.conf', help='Configuration file path')
    
    args = parser.parse_args()
    
    try:
        # Create debug proxy
        proxy = TTLVDebugProxy(config_file=args.configuration)
        
        print("Opening connection for TTLV debugging...")
        proxy.open()
        
        print("Attempting minimal query to debug TTLV parsing...")
        
        # Try the simplest possible query
        result = proxy.query(query_functions=[enums.QueryFunction.QUERY_OPERATIONS])
        
        print("Query succeeded!")
        print(f"Operations: {[op.value for op in result.operations]}")
        
    except Exception as e:
        print(f"Debug failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        if 'proxy' in locals():
            proxy.close()

if __name__ == "__main__":
    main()
