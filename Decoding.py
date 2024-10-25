import base64
import codecs
import binascii
import zlib
import json
from urllib.parse import unquote

def decode_text(encoded_text):
    decoding_methods = {
        "base64": decode_base64,
        "hex": decode_hex,
        "url": decode_url,
        "rot13": decode_rot13,
        "utf-16": decode_utf16_bytes,
        "utf-16le": decode_utf16le,
        "utf-16be": decode_utf16be,
        "ascii85": decode_ascii85,
        "quoted-printable": decode_quoted_printable,
        "utf-7": decode_utf7,
        "utf-32": decode_utf32,
        "zlib": decode_zlib,
        "base32": decode_base32,
        "rot47": decode_rot47,
        "uuencode": decode_uuencode,
        "binary": decode_binary,
        "base16": decode_base16,
        "cisco7": decode_cisco_type_7,
        "morse": decode_morse,
        "json": decode_json,
        # Add more decoding methods here
    }

    for name, method in decoding_methods.items():
        try:
            result = method(encoded_text)
            if result:  # Check if decoding was successful
                return f"Decoded with {name}: {result}"
        except Exception as e:
            # You can log the error here if needed
            continue

    return "Failed to decode with all methods."

def decode_base64(encoded_text):
    return base64.b64decode(encoded_text).decode("utf-8", errors='ignore')

def decode_hex(encoded_text):
    return bytes.fromhex(encoded_text).decode("utf-8", errors='ignore')

def decode_url(encoded_text):
    return unquote(encoded_text)

def decode_rot13(encoded_text):
    return codecs.decode(encoded_text, "rot_13")

def decode_utf16_bytes(encoded_text):
    utf16_bytes = encoded_text.encode('utf-16')
    return utf16_bytes.decode('utf-16', 'ignore')

def decode_utf16le(encoded_text):
    return encoded_text.encode('utf-16le').decode('utf-16le', errors='ignore')

def decode_utf16be(encoded_text):
    return encoded_text.encode('utf-16be').decode('utf-16be', errors='ignore')

def decode_ascii85(encoded_text):
    return codecs.decode(encoded_text.encode(), 'ascii85').decode('utf-8', errors='ignore')

def decode_quoted_printable(encoded_text):
    return codecs.decode(encoded_text, 'quopri')

def decode_utf7(encoded_text):
    return base64.b64decode(encoded_text).decode('utf-7', errors='ignore')

def decode_utf32(encoded_text):
    return base64.b64decode(encoded_text).decode('utf-32', errors='ignore')

def decode_zlib(encoded_text):
    return zlib.decompress(base64.b64decode(encoded_text)).decode('utf-8', errors='ignore')

def decode_base32(encoded_text):
    return base64.b32decode(encoded_text).decode("utf-8", errors='ignore')

def decode_rot47(encoded_text):
    return ''.join(chr((ord(char) - 33 + 47) % 94 + 33) if 33 <= ord(char) <= 126 else char for char in encoded_text)

def decode_uuencode(encoded_text):
    return codecs.decode(encoded_text.encode(), 'uu')

def decode_binary(encoded_text):
    binary_values = encoded_text.split()
    ascii_characters = [chr(int(bv, 2)) for bv in binary_values]
    return ''.join(ascii_characters)

def decode_base16(encoded_text):
    return binascii.unhexlify(encoded_text).decode("utf-8", errors='ignore')

def decode_cisco_type_7(encoded_text):
    # Decode Cisco Type 7 passwords
    decoded = ""
    for char in encoded_text:
        decoded += chr(ord(char) ^ 0x9E)
    return decoded

def decode_morse(encoded_text):
    morse_dict = {
        '.-': 'A', '-...': 'B', '-..': 'D', '-..-': 'X', 
        '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', 
        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', 
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', 
        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', 
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', 
        '-.--': 'Y', '--..': 'Z', ' ': ' '
    }
    return ''.join(morse_dict.get(code, '') for code in encoded_text.split())

def decode_json(encoded_text):
    return json.loads(encoded_text)

# Main function
if __name__ == "__main__":
    encoded_text = input("Enter the encoded text: ")
    decoded_text = decode_text(encoded_text)
    print("Decoded text:", decoded_text)
