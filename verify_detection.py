import sys
from analyzer import detect_encryption, analyze_crypto_code

def test(name, code, expected_detection, expected_issues):
    print(f"\n--- Testing: {name} ---")
    detection = detect_encryption(code)
    issues = analyze_crypto_code(code)
    
    print(f"Detection: {repr(detection)}")
    print(f"Issues Found: {len(issues)}")
    for i in issues:
        print(f" - {i['type']}: {i['problem']}")

    # Verification
    if expected_detection and expected_detection not in detection:
        print(f"FAILED: Expected detection '{expected_detection}' not found.")
    
    found_issue_types = [i['type'] for i in issues]
    for exp_issue in expected_issues:
        if exp_issue not in found_issue_types:
            print(f"FAILED: Expected issue '{exp_issue}' not found.")
            
    if expected_detection in detection and all(i in found_issue_types for i in expected_issues):
        print("PASSED")

# Test Cases

# 1. Explicit ECB Mode (AST should catch this)
code_ecb = """
from Crypto.Cipher import AES
cipher = AES.new(b'1234567890123456', AES.MODE_ECB)
"""
test("AES ECB Mode", code_ecb, "Algorithm: AES", ["AES Mode", "Hardcoded Keys"])

# 2. Hardcoded Weak Key (AST should catch this)
code_weak_key = """
key = b'weak'
"""
test("Weak Key", code_weak_key, "No recognizable", ["AES Key", "Hardcoded Keys"])

# 3. Fernet (AST should catch this)
code_fernet = """
from cryptography.fernet import Fernet
key = Fernet.generate_key()
"""
test("Fernet", code_fernet, "Algorithm: Fernet", [])

# 4. Syntax Error (Should fallback to Regex)
code_syntax_error = """
from Crypto.Cipher import AES
this is not valid python code
cipher = AES.new(key, AES.MODE_ECB)
"""
test("Syntax Error (Fallback)", code_syntax_error, "AES Encryption", ["AES Mode"])

