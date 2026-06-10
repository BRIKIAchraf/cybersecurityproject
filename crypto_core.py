import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

def derive_keys(shared_secret: bytes):
    """Derives encryption and MAC keys from a shared secret."""
    # Module 1 & 2: Derive 2 keys: one for AES-CTR, one for HMAC-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64, # 32 bytes for AES-256, 32 bytes for HMAC-SHA256
        salt=None,
        info=b'handshake data',
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:]

def encrypt_message(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt-then-MAC using AES-CTR and HMAC-SHA256."""
    # 1. Encrypt (Module 1 - Confidentiality)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # 2. MAC over nonce + ciphertext (Module 2 - Integrity)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    mac_tag = h.finalize()
    
    # Return nonce + ciphertext + MAC
    return nonce + ciphertext + mac_tag

def decrypt_message(enc_key: bytes, mac_key: bytes, data: bytes) -> bytes:
    """Verifies MAC then decrypts using AES-CTR."""
    if len(data) < 16 + 32:
        raise ValueError("Données trop courtes.")
        
    nonce = data[:16]
    mac_tag = data[-32:]
    ciphertext = data[16:-32]
    
    # 1. Verify MAC (Module 2 - Integrity)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    try:
        h.verify(mac_tag)
    except InvalidSignature:
        raise ValueError("MAC invalide — paquet rejeté")
        
    # 2. Decrypt (Module 1 - Confidentiality)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext
