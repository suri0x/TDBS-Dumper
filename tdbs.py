import re
import sys
 
if len(sys.argv) < 2:
    print("Usage: python3 unhex.py <binary_path>")
    sys.exit(1)

def tdbs_extract(binary_path: str, min_length=4) -> list[str]:
    printable_chars = set(bytes(range(32, 127))); strings = []; current_string = bytearray()

    with open(binary_path, 'rb') as f:
        while chunk := f.read(1024):
            for byte in chunk:
                if byte in printable_chars:
                    current_string.append(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string.decode('ascii'))
                    current_string = bytearray()
            if len(current_string) >= min_length:
                strings.append(current_string.decode('ascii'))
                current_string = bytearray()
    return strings

def tdbs_filter(strings: list[str]) -> list[str]:
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return [s for s in strings if hex_pattern.match(s)]

def tdbs_decrypt(hex_string: str) -> str:
    try:
        encrypted_bytes = bytes.fromhex(hex_string)
    except ValueError as e:
        print(f"Error converting hex string to bytes: {e}, hex_string: '{hex_string}'")
        return "Error in decryption" 
    
    decrypted_bytes = []
    previous_byte = 0
    for current_byte in encrypted_bytes:
        decrypted_byte = current_byte ^ previous_byte
        decrypted_bytes.append(decrypted_byte)
        previous_byte = current_byte
    decrypted_string = bytes(decrypted_bytes).decode('utf-8', errors='replace')
    return decrypted_string

def main():
    binary_path = sys.argv[1]
    strings = tdbs_extract(binary_path, min_length=4); hex_strings = tdbs_filter(strings)

    print(f'Extracted {len(strings)} strings from the binary file.')
    print(f'Filtered {len(hex_strings)} hex strings.')

    decrypted_strings = [tdbs_decrypt(s) for s in hex_strings]

    print(f'Decrypted {len(decrypted_strings)} strings.')
    for decrypted_string in decrypted_strings:
        print(decrypted_string)

if __name__ == "__main__":
    main()
