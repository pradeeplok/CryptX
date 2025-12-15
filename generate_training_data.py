"""
Generate synthetic training data for cipher identification ML model.
Creates labeled samples from known cryptographic algorithms.
SIH-1681 Phase 2: Enhanced Dataset
"""

import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import csv
import numpy as np
from cipher_classifier import classifier  # Use consistent feature extraction

def generate_aes_sample(key_size=16, mode_name='CBC'):
    """Generate AES encrypted sample."""
    key = secrets.token_bytes(key_size)
    iv = secrets.token_bytes(16)
    plaintext = secrets.token_bytes(secrets.choice([64, 128, 256, 512, 1024]))
    
    # Pad if needed
    if mode_name != 'GCM' and mode_name != 'CTR':
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len] * pad_len)
    
    if mode_name == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        label = f"AES-{key_size*8} (CBC)"
    elif mode_name == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        label = f"AES-{key_size*8} (ECB)"
    elif mode_name == 'GCM':
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        label = f"AES-{key_size*8} (GCM)"
    else:  # CTR
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        label = f"AES-{key_size*8} (CTR)"
    
    return ciphertext, label

def generate_chacha20_sample():
    """Generate ChaCha20 sample."""
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    plaintext = secrets.token_bytes(secrets.choice([64, 256, 512, 1024]))
    
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, "ChaCha20"

def generate_des_sample(mode='CBC'):
    """Generate DES encrypted sample."""
    key = secrets.token_bytes(8)
    iv = secrets.token_bytes(8)
    plaintext = secrets.token_bytes(secrets.choice([64, 128, 256]))
    
    pad_len = 8 - (len(plaintext) % 8)
    plaintext += bytes([pad_len] * pad_len)
    
    if mode == 'ECB':
        cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB(), backend=default_backend())
        label = "DES (ECB)"
    else:
        cipher = Cipher(algorithms.TripleDES(key * 3), modes.CBC(iv), backend=default_backend())
        label = "DES (CBC)"
        
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, label

def generate_rsa_sample(key_size=2048):
    """Generate RSA encrypted sample."""
    # RSA is slow, so we optimize by generating keys once per batch if needed, 
    # but for quality we generate fresh keys here (slower but better).
    # To speed up generation for this demo, we'll use a small pool or pre-generated keys in a real app.
    # For now, we limit the count or use smaller keys for dev.
    
    # NOTE: Generating RSA keys is extremely cpu intensive. 
    # For training data, we might just simulate random data of specific lengths
    # since RSA encrypted data is indistinguishable from random noise except for length.
    
    # Simulating RSA ciphertext properties (Random bytes of key_size length)
    length = key_size // 8
    ciphertext = secrets.token_bytes(length)
    label = f"RSA-{key_size}"
    return ciphertext, label

def generate_dataset(samples_per_algorithm=200, output_file='training_data.csv'):
    """Generate complete training dataset."""
    print(f"Generating training dataset with ~{samples_per_algorithm} samples per class...")
    
    dataset = []
    
    # 1. AES Variants
    for _ in range(samples_per_algorithm):
        # Mixed keys/modes
        for k in [16, 24, 32]:
            for m in ['CBC', 'ECB', 'GCM', 'CTR']:
                ct, lbl = generate_aes_sample(k, m)
                feats = classifier.extract_features_vector(ct)
                dataset.append({'features': feats, 'label': lbl})

    # 2. ChaCha20
    for _ in range(samples_per_algorithm * 4): # More samples to balance against AES variants
        ct, lbl = generate_chacha20_sample()
        feats = classifier.extract_features_vector(ct)
        dataset.append({'features': feats, 'label': lbl})

    # 3. DES Variants
    for _ in range(samples_per_algorithm * 2):
        for m in ['CBC', 'ECB']:
            ct, lbl = generate_des_sample(m)
            feats = classifier.extract_features_vector(ct)
            dataset.append({'features': feats, 'label': lbl})
            
    # 4. RSA Variants (Simulated)
    for _ in range(samples_per_algorithm):
        for k in [1024, 2048, 4096]:
            ct, lbl = generate_rsa_sample(k)
            feats = classifier.extract_features_vector(ct)
            dataset.append({'features': feats, 'label': lbl})

    # Save to CSV
    print(f"Saving {len(dataset)} samples to {output_file}...")
    with open(output_file, 'w', newline='') as f:
        # Create headers based on feature vector
        # [entropy, block_8, block_16, block_32, skew, kurt, chi2, auto, comp, bigram]
        headers = [
            'entropy', 'block_rep_8', 'block_rep_16', 'block_rep_32',
            'skewness', 'kurtosis', 'chi2_stat', 'autocorrelation',
            'compression_ratio', 'bigram_rep', 'label'
        ]
        
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for item in dataset:
            row = item['features'] + [item['label']]
            writer.writerow(row)
    
    print(f"Dataset generated successfully!")
    print(f"Total samples: {len(dataset)}")

if __name__ == "__main__":
    generate_dataset(samples_per_algorithm=50, output_file='d:/CryptX-main/training_data.csv')

