from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

def generate_dh_private_key():
    """Generates an Elliptic Curve Diffie-Hellman private key."""
    return ec.generate_private_key(ec.SECP256R1())

def get_public_bytes(private_key):
    """Exports the public key to bytes for transmission."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pub_bytes):
    """Loads a public key from bytes."""
    return serialization.load_pem_public_key(pub_bytes)

def compute_shared_secret(private_key, peer_public_key_bytes):
    """Computes the shared secret from private key and peer's public key."""
    peer_public_key = load_public_key(peer_public_key_bytes)
    return private_key.exchange(ec.ECDH(), peer_public_key)

# Optional: Signatures for Module 3 (Authentication)
def sign_data(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

def verify_signature(public_key, signature: bytes, data: bytes):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
