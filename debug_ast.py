from analyzer import detect_encryption

code = """
from Crypto.Cipher import AES
cipher = AES.new(b'1234567890123456', AES.MODE_ECB)
"""

print("--- DEBUG ---")
try:
    result = detect_encryption(code)
    print(f"RESULT: {result}")
except Exception as e:
    print(f"ERROR: {e}")
