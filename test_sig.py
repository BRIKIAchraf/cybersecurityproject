from trusted_keys import ALICE_IDENTITY_PRIV, ALICE_IDENTITY_PUB_BYTES
from dh_handshake import sign_data, verify_signature, load_public_key

test_data = b"Hello world"
sig = sign_data(ALICE_IDENTITY_PRIV, test_data)
pub_key = load_public_key(ALICE_IDENTITY_PUB_BYTES)
is_valid = verify_signature(pub_key, sig, test_data)
print(f"Signature is valid: {is_valid}")
