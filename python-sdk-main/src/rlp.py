from typing import List, Union, Tuple, Dict, Any, Optional
import binascii

# Define Input type
Input = Union[str, int, bytes, List['Input'], Tuple['Input', ...], None]

def to_bytes(input_data: Input) -> bytes:
    """Convert input to bytes"""
    if input_data is None:
        return b''
    elif isinstance(input_data, bytes):
        return input_data
    elif isinstance(input_data, str):
        if input_data.startswith('0x'):
            return binascii.unhexlify(input_data[2:])
        return input_data.encode('utf-8')
    elif isinstance(input_data, int):
        return input_data.to_bytes((input_data.bit_length() + 7) // 8, 'big') if input_data > 0 else b'\x00'
    elif isinstance(input_data, (list, tuple)):
        # Handle both lists and tuples the same way
        return encode(input_data)  # Recursively encode lists/tuples
    else:
        raise TypeError(f"Unsupported type: {type(input_data)}")

def encode_length(length: int, offset: int) -> bytes:
    """Encode the length of an RLP item"""
    if length < 56:
        return bytes([length + offset])
    
    hex_length = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    first_byte = offset + 55 + len(hex_length)
    return bytes([first_byte]) + hex_length

def encode(input_data: Input) -> bytes:
    """RLP Encoding based on Ethereum's RLP specification"""
    if isinstance(input_data, (list, tuple)):
        output = b''
        for item in input_data:
            output += encode(item)
        return encode_length(len(output), 0xc0) + output
    
    # Convert to bytes if not already
    if not isinstance(input_data, bytes):
        input_bytes = to_bytes(input_data)
    else:
        input_bytes = input_data
        
    if len(input_bytes) == 1 and input_bytes[0] < 128:
        return input_bytes
    
    return encode_length(len(input_bytes), 0x80) + input_bytes

def decode(input_data: Input) -> Union[bytes, List[Any]]:
    """RLP Decoding based on Ethereum's RLP specification"""
    input_bytes = to_bytes(input_data)
    if not input_bytes:
        return b''
    
    result, remainder = _decode(input_bytes)
    if remainder:
        raise ValueError("Invalid RLP: remainder must be zero")
    
    return result

def _decode(input_bytes: bytes) -> Tuple[Union[bytes, List[Any]], bytes]:
    """Internal RLP decoding function"""
    if not input_bytes:
        return b'', b''
    
    first_byte = input_bytes[0]
    
    if first_byte <= 0x7f:
        # Single byte
        return input_bytes[:1], input_bytes[1:]
    elif first_byte <= 0xb7:
        # Short string
        length = first_byte - 0x80
        if len(input_bytes) < length + 1:
            raise ValueError("Invalid RLP: not enough bytes for string")
        
        if length == 1 and input_bytes[1] < 0x80:
            raise ValueError("Invalid RLP: single byte < 0x80 should not be prefixed")
        
        return input_bytes[1:length+1], input_bytes[length+1:]
    elif first_byte <= 0xbf:
        # Long string
        ll_length = first_byte - 0xb7
        if len(input_bytes) < ll_length + 1:
            raise ValueError("Invalid RLP: not enough bytes for string length")
        
        length = int.from_bytes(input_bytes[1:ll_length+1], 'big')
        if length <= 55:
            raise ValueError("Invalid RLP: expected string length > 55")
        
        if len(input_bytes) < ll_length + 1 + length:
            raise ValueError("Invalid RLP: not enough bytes for string")
        
        return input_bytes[ll_length+1:ll_length+1+length], input_bytes[ll_length+1+length:]
    elif first_byte <= 0xf7:
        # Short list
        length = first_byte - 0xc0
        if len(input_bytes) < length + 1:
            raise ValueError("Invalid RLP: not enough bytes for list")
        
        remainder = input_bytes[1:length+1]
        result = []
        
        while remainder:
            item, remainder = _decode(remainder)
            result.append(item)
        
        return result, input_bytes[length+1:]
    else:
        # Long list
        ll_length = first_byte - 0xf7
        if len(input_bytes) < ll_length + 1:
            raise ValueError("Invalid RLP: not enough bytes for list length")
        
        length = int.from_bytes(input_bytes[1:ll_length+1], 'big')
        if length < 56:
            raise ValueError("Invalid RLP: encoded list too short")
        
        total_length = ll_length + 1 + length
        if len(input_bytes) < total_length:
            raise ValueError("Invalid RLP: not enough bytes for list")
        
        remainder = input_bytes[ll_length+1:total_length]
        result = []
        
        while remainder:
            item, remainder = _decode(remainder)
            result.append(item)
        
        return result, input_bytes[total_length:]