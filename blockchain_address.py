import hashlib
import os

# Simplification pour ne pas dépendre de la librairie base58 externe complexe
# On implémente un encodeur Base58 basique pour la démonstration
ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(ALPHABET[r])
    for char in b:
        if char == 0:
            res.append(ALPHABET[0])
        else:
            break
    return bytes(reversed(res)).decode('ascii')

def generate_bitcoin_address(public_key_bytes: bytes) -> str:
    # 1. SHA-256 de la clé publique
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    
    # 2. RIPEMD-160
    # Note: RIPEMD-160 n'est pas toujours disponible dans hashlib standard sur tous les systèmes.
    # Pour garantir que ça marche, on utilise un SHA-256 tronqué à 20 octets si RIPEMD plante.
    try:
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_pk)
        hashed_pk = ripemd160.digest()
    except ValueError:
        print("[!] RIPEMD-160 non disponible, utilisation d'un SHA-256 tronqué pour la simulation.")
        hashed_pk = hashlib.sha256(sha256_pk).digest()[:20]
    
    # 3. Ajouter le byte de version (0x00 pour Mainnet Bitcoin)
    network_byte = b'\x00' + hashed_pk
    
    # 4. Calculer le checksum (Double SHA-256)
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # 5. Concaténer et encoder en Base58
    address_bytes = network_byte + checksum
    address = b58encode(address_bytes)
    return address

if __name__ == "__main__":
    print("==========================================================")
    print("--- Module 6 : Nouvelles Technologies (Blockchain Crypto) ---")
    print("==========================================================\n")
    
    # Clé publique factice (ex: issue d'ECDSA secp256k1)
    fake_pub_key = b'\x04' + os.urandom(64)
    print(f"1. Clé Publique (brute) : {fake_pub_key.hex()[:30]}...")
    
    btc_address = generate_bitcoin_address(fake_pub_key)
    print(f"2. Adresse Bitcoin Générée : {btc_address}")
