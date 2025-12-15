from analyzer import detect_encryption, analyze_crypto_code

def test():
    results = []
    
    # 1. Explicit ECB Mode
    code_ecb = """
from Crypto.Cipher import AES
cipher = AES.new(b'1234567890123456', AES.MODE_ECB)
"""
    det = detect_encryption(code_ecb)
    issues = analyze_crypto_code(code_ecb)
    results.append(f"Test 1 Detection: {det}")
    results.append(f"Test 1 Issues: {[i['type'] for i in issues]}")

    # 2. Fernet
    code_fernet = """
from cryptography.fernet import Fernet
key = Fernet.generate_key()
"""
    det = detect_encryption(code_fernet)
    results.append(f"Test 2 Detection: {det}")

    with open("verify_result.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(results))

if __name__ == "__main__":
    test()
