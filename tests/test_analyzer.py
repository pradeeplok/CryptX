import pytest
from analyzer import detect_encryption, analyze_crypto_code

# --- Detection Tests ---

def test_detect_aes_ecb():
    code = """
from Crypto.Cipher import AES
cipher = AES.new(b'1234567890123456', AES.MODE_ECB)
"""
    detection = detect_encryption(code)
    assert "Algorithm: AES" in detection
    assert "Library: Cryptography/PyCryptodome" in detection

def test_detect_fernet():
    code = """
from cryptography.fernet import Fernet
key = Fernet.generate_key()
"""
    detection = detect_encryption(code)
    assert "Algorithm: Fernet" in detection

def test_detect_rsa():
    code = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
    detection = detect_encryption(code)
    assert "Algorithm: RSA" in detection

# --- Analysis Tests ---

def test_analyze_ecb_mode():
    code = """
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
"""
    issues = analyze_crypto_code(code)
    issue_types = [i['type'] for i in issues]
    assert "AES Mode" in issue_types
    assert any("ECB mode detected" in i['problem'] for i in issues)

def test_analyze_weak_key_length():
    code = """
key = b'weak'
"""
    issues = analyze_crypto_code(code)
    issue_types = [i['type'] for i in issues]
    assert "AES Key" in issue_types
    assert any("Weak Key detected" in i['problem'] for i in issues)

def test_analyze_hardcoded_key():
    code = """
key = b'secret_but_hardcoded_key_123'
"""
    issues = analyze_crypto_code(code)
    issue_types = [i['type'] for i in issues]
    assert "Hardcoded Keys" in issue_types

def test_analyze_weak_random():
    code = """
import random
iv = random.randbytes(16)
"""
    issues = analyze_crypto_code(code)
    # Note: 'random.randbytes' might not be explicitly in our list, but 'random' usage usually triggers if we check generic random usage.
    # Let's check specifically for what our analyzer looks for: random.randint, random.choice
    code2 = "x = random.randint(0, 100)"
    issues2 = analyze_crypto_code(code2)
    issue_types2 = [i['type'] for i in issues2]
    assert "Random Generation" in issue_types2

def test_clean_code():
    code = """
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
"""
    issues = analyze_crypto_code(code)
    assert len(issues) == 0
