import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_layer(key, data):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(data) + encryptor.finalize()

def decrypt_layer(key, data):
    nonce, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

if __name__ == "__main__":
    print("==================================================")
    print("--- Scénario 1 : Routage Anonyme (Onion Routing) ---")
    print("==================================================\n")
    
    # Clés partagées entre Alice et les relais (Phil, Phoebe) et Bob
    key_phil = os.urandom(32)
    key_phoebe = os.urandom(32)
    key_bob = os.urandom(32)
    
    message = b"Secret Mission Coordinates: 45.9, 12.4"
    print(f"[*] Message original d'Alice : {message.decode()}")
    
    # Alice construit l'Oignon (Chiffrement en couches)
    print("\n[+] Alice prépare l'oignon...")
    layer_bob = encrypt_layer(key_bob, b"DEST:BOB|" + message)
    layer_phoebe = encrypt_layer(key_phoebe, b"NEXT:BOB|" + layer_bob)
    layer_phil = encrypt_layer(key_phil, b"NEXT:PHOEBE|" + layer_phoebe)
    
    print(f"[!] Paquet final envoyé sur le réseau (Taille: {len(layer_phil)} octets)")
    
    # Le trajet réseau
    print("\n[>] Arrivée au Relais 1 (Phil)")
    decrypted_phil = decrypt_layer(key_phil, layer_phil)
    next_hop_1, payload_1 = decrypted_phil.split(b'|', 1)
    print(f"    Instruction lue par Phil : {next_hop_1.decode()}")
    
    print("\n[>] Arrivée au Relais 2 (Phoebe)")
    decrypted_phoebe = decrypt_layer(key_phoebe, payload_1)
    next_hop_2, payload_2 = decrypted_phoebe.split(b'|', 1)
    print(f"    Instruction lue par Phoebe : {next_hop_2.decode()}")
    
    print("\n[>] Arrivée à Destination (Bob)")
    decrypted_bob = decrypt_layer(key_bob, payload_2)
    final_dest, final_message = decrypted_bob.split(b'|', 1)
    print(f"    Destination confirmée : {final_dest.decode()}")
    print(f"    => Message déchiffré par Bob : {final_message.decode()}")
    
    print("\n[OK] Succès : Phil et Phoebe ignorent le contenu du message et ignorent qui sont l'expéditeur initial et le destinataire final globaux.")
