import re
import os
import base64
import google.generativeai as genai
from PIL import Image, ImageDraw
import io

# ---------------- EXPLAINABILITY LAYER ----------------
def create_ecb_demo():
    """Create a visual demonstration of ECB mode pattern leakage"""
    # Create a simple image with patterns
    img = Image.new('RGB', (200, 200), color='white')
    draw = ImageDraw.Draw(img)
    
    # Draw some patterns that will show ECB weakness
    for i in range(0, 200, 20):
        draw.rectangle([i, 0, i+10, 200], fill='red')
        draw.rectangle([i+10, 0, i+20, 200], fill='blue')
    
    # Convert to bytes for demonstration
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_data = img_buffer.getvalue()
    
    return {
        "original_size": len(img_data),
        "pattern_description": "Red and blue stripes every 20 pixels",
        "explanation": "ECB mode will encrypt identical blocks identically, making patterns visible even after encryption"
    }

def create_cbc_demo():
    """Create a visual demonstration of CBC mode (random noise)"""
    # Create the same pattern image
    img = Image.new('RGB', (200, 200), color='white')
    draw = ImageDraw.Draw(img)
    for i in range(0, 200, 20):
        draw.rectangle([i, 0, i+10, 200], fill='red')
        draw.rectangle([i+10, 0, i+20, 200], fill='blue')
    
    # In a real CBC encryption of an image, the result looks like random noise
    # We simulate this by generating random pixels
    noise_img = Image.effect_noise((200, 200), 50)
    
    img_buffer = io.BytesIO()
    noise_img.save(img_buffer, format='PNG')
    img_data = img_buffer.getvalue()
    
    return {
        "image_data": base64.b64encode(img_data).decode('utf-8'),
        "explanation": "CBC mode uses an IV and chaining, so identical blocks encrypt to different ciphertext. The result is indistinguishable from random noise."
    }

def create_bitflip_demo():
    """Demonstrate CBC Bit Flipping Attack"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Message to encrypt (needs to be block aligned for simplicity here)
    msg = b"Transfer $1000 to Account: Alice"
    # Pad manually to 32 bytes
    msg_padded = msg + b' ' * (32 - len(msg))
    
    ciphertext = encryptor.update(msg_padded) + encryptor.finalize()
    
    # Attack: Flip a bit in the first block of ciphertext
    # This will scramble the first block of plaintext, but flip the corresponding bit in the second block
    # Target: Change "Alice" to "Mallory" (or just break it)
    # Let's just flip the last byte of the IV (which acts as the previous block for the first block)
    # Or flip a byte in the first ciphertext block to affect the second plaintext block
    
    # Let's try to change "Alice" (at index 27) to something else
    # "Alice" is in the second block (indices 16-31)
    # To flip bit at index 27 in plaintext, we flip bit at index 27-16=11 in the PREVIOUS ciphertext block (which is the IV here if it's the first block, or first ciphertext block if it's the second)
    # Wait, msg is 32 bytes. 2 blocks.
    # Block 1: "Transfer $1000 t"
    # Block 2: "o Account: Alice"
    # To change 'A' (index 11 in block 2) in block 2, we modify byte 11 in block 1 of ciphertext.
    
    # Convert ciphertext to mutable bytearray
    ct_array = bytearray(ciphertext)
    
    # Target 'A' in "Alice" (0x41). Let's change it to 'M' (0x4D).
    # XOR difference: 0x41 ^ 0x4D = 0x0C
    # We apply this XOR to the corresponding byte in the previous block (ciphertext block 1, index 11)
    # "Transfer $1000 t" -> index 11 is '1' (0x31)
    
    # The byte to change in ciphertext is index 11
    ct_array[11] ^= 0x0C
    
    # Decrypt modified ciphertext
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(bytes(ct_array)) + decryptor.finalize()
    
    return {
        "original": msg_padded.decode(),
        "modified_ciphertext_hex": ct_array.hex(),
        "decrypted": decrypted_padded.decode(errors='replace'),
        "explanation": "Modifying a byte in ciphertext block N scrambles plaintext block N, but predictably flips bits in plaintext block N+1. Note how 'Alice' became 'Mlice' but the previous block is garbage."
    }

def generate_secure_code_snippets(issues, code):
    """Generate secure corrected code snippets for educational purposes"""
    snippets = {}
    
    for issue in issues:
        if issue["type"] == "AES Mode" and "ECB" in issue["problem"]:
            snippets["ecb_fix"] = {
                "title": "Replace ECB with CBC Mode",
                "description": "ECB mode leaks patterns. Here's a secure CBC implementation:",
                "code": '''from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def encrypt_with_cbc(plaintext, password):
    # Generate a random salt and derive key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad plaintext to block size
    padded_data = plaintext.encode() + b'\\x00' * (16 - len(plaintext.encode()) % 16)
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return salt + iv + ciphertext

def decrypt_with_cbc(ciphertext, password):
    # Extract salt, IV, and encrypted data
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    encrypted_data = ciphertext[32:]
    
    # Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    plaintext = padded_data.rstrip(b'\\x00').decode()
    return plaintext''',
                "security_features": [
                    "Random salt for key derivation",
                    "Random IV for each encryption",
                    "PBKDF2 with 100,000 iterations",
                    "Proper padding handling"
                ]
            }
        
        elif issue["type"] == "AES Key" and "Weak" in issue["problem"]:
            snippets["key_fix"] = {
                "title": "Generate Strong AES Key",
                "description": "Generate cryptographically secure random keys:",
                "code": '''import secrets
import base64

# Generate a strong 256-bit (32-byte) key
def generate_strong_key():
    return secrets.token_bytes(32)

# Generate a key and encode it for storage
def generate_and_encode_key():
    key = generate_strong_key()
    encoded_key = base64.b64encode(key).decode('utf-8')
    return key, encoded_key

# Example usage
key, encoded_key = generate_and_encode_key()
print(f"Generated key (hex): {key.hex()}")
print(f"Encoded key (base64): {encoded_key}")

# For Fernet (requires base64-encoded key)
from cryptography.fernet import Fernet
fernet_key = Fernet.generate_key()
print(f"Fernet key: {fernet_key.decode()}")''',
                "security_features": [
                    "Uses secrets module (cryptographically secure)",
                    "256-bit key length (AES-256)",
                    "Base64 encoding for storage/transmission",
                    "No hardcoded keys in source code"
                ]
            }
        
        elif issue["type"] == "CBC IV" and "without IV" in issue["problem"]:
            snippets["iv_fix"] = {
                "title": "Add Proper IV Handling",
                "description": "Always use random IVs for CBC mode:",
                "code": '''import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_with_proper_iv(plaintext, key):
    # Generate random IV for each encryption
    iv = os.urandom(16)
    
    # Create cipher with IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad and encrypt
    padded_data = plaintext.encode() + b'\\x00' * (16 - len(plaintext.encode()) % 16)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + ciphertext (IV must be stored/transmitted with ciphertext)
    return iv + ciphertext

def decrypt_with_proper_iv(ciphertext, key):
    # Extract IV from beginning of ciphertext
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    # Create cipher with extracted IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    plaintext = padded_data.rstrip(b'\\x00').decode()
    return plaintext

# Example usage
key = os.urandom(32)  # 256-bit key
message = "Hello, secure world!"
encrypted = encrypt_with_proper_iv(message, key)
decrypted = decrypt_with_proper_iv(encrypted, key)
print(f"Original: {message}")
print(f"Decrypted: {decrypted}")''',
                "security_features": [
                    "Random IV for each encryption",
                    "IV stored with ciphertext",
                    "Proper padding handling",
                    "Secure random number generation"
                ]
            }
    
    return snippets

import ast

# ---------------- DETECTION ----------------
def detect_encryption(code):
    """
    Detect encryption libraries and algorithms using AST parsing.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Fallback for non-Python code or snippets with syntax errors
        return _detect_encryption_regex(code)

    detected = set()

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if 'cryptography' in alias.name or 'Crypto' in alias.name:
                    detected.add('Library: Cryptography/PyCryptodome')
        elif isinstance(node, ast.ImportFrom):
            if node.module and ('cryptography' in node.module or 'Crypto' in node.module):
                detected.add('Library: Cryptography/PyCryptodome')
            
            # Check imported names for algorithms
            for alias in node.names:
                if alias.name == 'AES':
                    detected.add('Algorithm: AES')
                elif alias.name == 'RSA':
                    detected.add('Algorithm: RSA')
                elif alias.name == 'Blowfish':
                    detected.add('Algorithm: Blowfish')
                elif alias.name == 'DES':
                    detected.add('Algorithm: DES')
                elif alias.name == 'ARC4':
                    detected.add('Algorithm: ARC4')
                elif alias.name == 'Fernet':
                    detected.add('Algorithm: Fernet')
                elif 'public_key' in alias.name or 'private_key' in alias.name:
                    detected.add('Algorithm: Public/Private Key')

        # Check for specific function calls / attributes (e.g. Cipher(algorithms.AES...))
        if isinstance(node, ast.Attribute):
            if node.attr == 'AES':
                detected.add('Algorithm: AES')
            elif node.attr == 'RSA':
                detected.add('Algorithm: RSA')
            elif node.attr == 'Blowfish':
                detected.add('Algorithm: Blowfish')
            elif node.attr == 'DES':
                detected.add('Algorithm: DES')
            elif node.attr == 'ARC4':
                detected.add('Algorithm: ARC4')
        
        # Check for Name usage (e.g. AES.new where AES is imported)
        if isinstance(node, ast.Name):
            if node.id == 'AES':
                detected.add('Algorithm: AES')
            elif node.id == 'RSA':
                detected.add('Algorithm: RSA')
            elif node.id == 'Fernet':
                detected.add('Algorithm: Fernet')

    if detected:
        return "Detected: " + ", ".join(sorted(detected))
    else:
        # Fallback to regex if AST missed everything (e.g. incomplete snippets)
        return _detect_encryption_regex(code)

def _detect_encryption_regex(code):
    code = code.lower()
    if 'cryptography.hazmat' in code or 'fernet' in code:
        return 'Detected: Fernet (Symmetric - Cryptography Module)'
    elif 'aes' in code and ('from cryptography' in code or 'pycryptodome' in code or 'from crypto' in code or 'import crypto' in code):
        return 'Detected: AES Encryption'
    elif 'rsa' in code and ('cryptography' in code or 'rsa.newkeys' in code):
        return 'Detected: RSA Encryption'
    elif 'blowfish' in code:
        return 'Detected: Blowfish Encryption'
    elif 'des' in code:
        return 'Detected: DES Encryption'
    elif 'arc4' in code:
        return 'Detected: ARC4 Stream Cipher'
    elif 'public_key' in code and 'private_key' in code:
        return 'Detected: Public/Private Key Encryption'
    else:
        return 'No recognizable encryption method detected.'


# ---------------- ANALYSIS ----------------
def analyze_crypto_code(code):
    issues = []
    is_python = True
    tree = None
    
    try:
        tree = ast.parse(code)
    except SyntaxError:
        is_python = False
        # Don't return yet! processed to generic analysis

    # Walk the AST only if it's Python
    if is_python and tree:
        for node in ast.walk(tree):
            # 1. Check for AES ECB Mode
            # Looking for: AES.new(..., AES.MODE_ECB) or modes.ECB()
            if isinstance(node, ast.Call):
                # Check for modes.ECB()
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'ECB':
                    issues.append({
                        "type": "AES Mode",
                        "problem": "ECB mode detected",
                        "explanation": "ECB mode leaks patterns. Use CBC/GCM instead.",
                        "severity": "HIGH",
                        "cve_reference": "CWE-327"
                    })
                # Check for AES.MODE_ECB usage in arguments
                for arg in node.args:
                    if isinstance(arg, ast.Attribute) and arg.attr == 'MODE_ECB':
                        issues.append({
                            "type": "AES Mode",
                            "problem": "ECB mode detected",
                            "explanation": "ECB mode leaks patterns. Use CBC/GCM instead.",
                            "severity": "HIGH",
                            "cve_reference": "CWE-327"
                        })

            # 2. Check for Weak Key Lengths (Hardcoded)
            # Looking for assignments like key = b'...' or key = '...'
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and 'key' in target.id.lower():
                        if isinstance(node.value, (ast.Constant, ast.Str, ast.Bytes)): # Python 3.8+ uses Constant
                            val = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
                            if isinstance(val, str):
                                val = val.encode()
                            
                            if len(val) < 16:
                                 issues.append({
                                    "type": "AES Key",
                                    "problem": f"Weak Key detected (length = {len(val)} bytes)",
                                    "explanation": f"Keys should be at least 16 bytes. Found {len(val)}.",
                                    "severity": "HIGH",
                                    "cve_reference": "CWE-326"
                                })
                            
                            # 3. Hardcoded Keys
                            # If we found a key assignment with a literal value, it's hardcoded!
                            if len(val) > 0:
                                 issues.append({
                                    "type": "Hardcoded Keys",
                                    "problem": "Hardcoded cryptographic key detected",
                                    "explanation": "Keys should be stored securely (env vars, KMS), not in source code.",
                                    "severity": "HIGH",
                                    "cve_reference": "CWE-321"
                                })

            # 4. Check for Weak Randomness
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['randint', 'choice', 'random'] and isinstance(node.func.value, ast.Name) and node.func.value.id == 'random':
                         issues.append({
                            "type": "Random Generation",
                            "problem": "Weak random number generation detected",
                            "explanation": "Use secrets module or os.urandom for cryptographic operations.",
                            "severity": "MEDIUM",
                            "cve_reference": "CWE-338"
                        })

    # 5. ML Analysis (Hybrid approach)
    # NOTE: Disabled by default to prevent blocking on large model download (500MB). 
    # Set ENABLE_ML = True to enable.
    ENABLE_ML = True 
    
    if ENABLE_ML:
        try:
            from ml_engine import engine
            ml_result = engine.analyze(code)
            if ml_result and ml_result.get('is_vulnerable'):
                # For non-Python code (where AST missed everything), ML is critical.
                confidence_msg = f"Confidence: {ml_result['confidence']:.2%}"
                issues.append({
                    "type": "ML Detection",
                    "problem": f"Potential Vulnerability ({confidence_msg})",
                    "explanation": "The AI model detected a pattern often associated with insecure code.",
                    "severity": "MEDIUM",
                    "cve_reference": "ML-Predicted"
                })
        except Exception as e:
            print(f"ML Analysis failed: {e}")

    # 5. Check for CBC without IV (Harder with AST alone without data flow, but we can check if IV is passed)
    # For now, let's keep the regex check for 'IV' existence as a heuristic backup or refine AST later.
    # Actually, let's rely on the AI for subtle missing IV cases, but check for explicit "MODE_CBC" without "iv=" kwarg if possible.
    
    # Merge with regex-based results for things AST might miss (like comments or partial code)
    regex_issues = _analyze_crypto_code_regex(code)
    
    # Deduplicate issues based on problem description
    seen_problems = set()
    unique_issues = []
    for i in issues + regex_issues:
        if i['problem'] not in seen_problems:
            seen_problems.add(i['problem'])
            unique_issues.append(i)

    return unique_issues

def _analyze_crypto_code_regex(code):
    issues = []
    # AES ECB MODE
    if "AES" in code and "MODE_ECB" in code:
        issues.append({
            "type": "AES Mode",
            "problem": "ECB mode detected",
            "explanation": "ECB mode leaks patterns. Use CBC/GCM instead.",
            "severity": "HIGH",
            "cve_reference": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
        })

    # AES Key Length - Improved regex for better security
    key_matches = re.findall(r'key\s*=\s*b?[\'"]([^\'"]+)[\'"]', code)
    for key in key_matches:
        try:
            key_len = len(key.encode('utf-8'))
            if key_len < 16:
                issues.append({
                    "type": "AES Key",
                    "problem": f"Weak AES key detected (length = {key_len} bytes)",
                    "explanation": f"AES requires >= 16 bytes. Found {key_len}.",
                    "severity": "HIGH",
                    "cve_reference": "CWE-326: Inadequate Encryption Strength"
                })
        except UnicodeEncodeError:
            pass

    # CBC Mode IV
    if "MODE_CBC" in code:
        has_iv = re.search(r'iv\s*=', code, re.IGNORECASE) or re.search(r'IV\s*=', code)
        if not has_iv:
            issues.append({
                "type": "CBC IV",
                "problem": "CBC mode without IV",
                "explanation": "CBC requires an initialization vector (IV).",
                "severity": "MEDIUM",
                "cve_reference": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
            })

    # Check for hardcoded keys
    if re.search(r'key\s*=\s*[\'"][^\'"]{8,}[\'"]', code):
        issues.append({
            "type": "Hardcoded Keys",
            "problem": "Hardcoded cryptographic keys detected",
            "explanation": "Keys should be stored securely, not in source code.",
            "severity": "HIGH",
            "cve_reference": "CWE-321: Use of Hard-coded Cryptographic Key"
        })

    # Check for weak random number generation
    if 'random.randint' in code or 'random.choice' in code:
        issues.append({
            "type": "Random Generation",
            "problem": "Weak random number generation detected",
            "explanation": "Use secrets module or os.urandom for cryptographic operations.",
            "severity": "MEDIUM",
            "cve_reference": "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator"
        })

    return issues


# ---------------- OPENAI SUGGESTIONS ----------------
def suggest_with_openai(issues, code):
    # CRITICAL FIX: Always analyze code, even if regex found no issues.
    # Regex is fragile; AI might find logic bugs or weak algorithms we missed.
    
    issue_summary = "No obvious issues found by static analysis."
    if issues:
        issue_summary = "\n".join(
            [f"- {i['problem']}: {i['explanation']}" for i in issues]
        )

    prompt = f"""
The following Python crypto code was analyzed:
{code}

Static Analysis Findings:
{issue_summary}

Your Task:
1. Review the code for cryptographic vulnerabilities that static analysis might have missed (e.g., weak algorithms like MD5/SHA1, insecure modes, hardcoded secrets, logic flaws).
2. If the static analysis found issues, explain how to fix them.
3. If no issues were found, DOUBLE CHECK. If it's truly secure, confirm it.
4. Provide secure, copy-pasteable code examples for any fixes.

Focus on practical, actionable advice.
"""

    try:
        # Configure Gemini
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        model = genai.GenerativeModel('models/gemini-1.5-flash-latest')
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error getting AI suggestions: {str(e)}. Please check your API key and internet connection."
