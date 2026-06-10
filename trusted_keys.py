import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ALICE_PRIV_FILE = 'alice_priv.pem'
BOB_PRIV_FILE = 'bob_priv.pem'

def get_or_create_key(filename):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = ec.generate_private_key(ec.SECP256R1())
        with open(filename, 'wb') as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return priv

# Static identity keys for the lab (Simulating Certificates)
ALICE_IDENTITY_PRIV = get_or_create_key(ALICE_PRIV_FILE)
ALICE_IDENTITY_PUB_BYTES = ALICE_IDENTITY_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

BOB_IDENTITY_PRIV = get_or_create_key(BOB_PRIV_FILE)
BOB_IDENTITY_PUB_BYTES = BOB_IDENTITY_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
