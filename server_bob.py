import socket
import logging
from config import HOST, BOB_PORT
from dh_handshake import generate_dh_private_key, get_public_bytes, compute_shared_secret, sign_data, verify_signature, load_public_key
from crypto_core import derive_keys, decrypt_message, encrypt_message
from logger_config import setup_logger
from trusted_keys import BOB_IDENTITY_PRIV, ALICE_IDENTITY_PUB_BYTES
from zkp_schnorr import Verifier, G, P

logger = setup_logger('Bob')

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, BOB_PORT))
    server.listen(1)
    logger.info(f"En écoute sur {HOST}:{BOB_PORT}...")
    
    conn, addr = server.accept()
    logger.info(f"Connexion de {addr}")
    
    try:
        # 1. Phase 1: Handshake AKE
        alice_data = b""
        while len(alice_data) < 250: # Ensure we receive the full packet (PEM + SIG is > 200 bytes)
            chunk = conn.recv(4096)
            if not chunk: break
            alice_data += chunk
            if b'---SIG---' in alice_data and len(alice_data.split(b'---SIG---')[1]) > 60:
                break
                
        if b'---SIG---' not in alice_data:
            logger.error("Format de poignée de main invalide.")
            return
            
        alice_pub_bytes, signature_alice = alice_data.split(b'---SIG---')
        
        # Vérification du certificat d'Alice (Défense MITM)
        alice_id_pub = load_public_key(ALICE_IDENTITY_PUB_BYTES)
        if not verify_signature(alice_id_pub, signature_alice, alice_pub_bytes):
            logger.error("[AKE CRITIQUE] Signature d'Alice invalide ! MITM Détecté. Connexion refusée.")
            return
            
        logger.info("Signature d'Alice vérifiée. Identité confirmée.")
        
        bob_priv = generate_dh_private_key()
        bob_pub_bytes = get_public_bytes(bob_priv)
        
        # Bob signe sa clé
        signature_bob = sign_data(BOB_IDENTITY_PRIV, bob_pub_bytes)
        conn.sendall(bob_pub_bytes + b'---SIG---' + signature_bob)
        
        shared_secret = compute_shared_secret(bob_priv, alice_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        logger.info("Clés dérivées. Canal sécurisé établi.")

        # 2. Phase 3: ZKP Administrateur
        secret_admin = 42
        alice_v_pub = pow(G, secret_admin, P) # Bob connait la clé publique admin d'Alice
        bob_verifier = Verifier(v=alice_v_pub)
        
        # Recevoir engagement (t)
        t_data = conn.recv(4096)
        t_str = decrypt_message(enc_key, mac_key, t_data).decode()
        t = int(t_str.split(':')[1])
        
        # Envoyer défi (c)
        c = bob_verifier.generate_challenge(t)
        conn.sendall(encrypt_message(enc_key, mac_key, f"ZKP_C:{c}".encode()))
        
        # Recevoir réponse (gamma)
        gamma_data = conn.recv(4096)
        gamma_str = decrypt_message(enc_key, mac_key, gamma_data).decode()
        gamma = int(gamma_str.split(':')[1])
        
        # Vérifier
        if bob_verifier.verify(t, gamma):
            logger.info("Preuve ZKP validée : Accès Administrateur accordé.")
            conn.sendall(encrypt_message(enc_key, mac_key, b"ACCES ADMIN OK"))
        else:
            logger.error("Preuve ZKP échouée : Accès refusé.")
            conn.sendall(encrypt_message(enc_key, mac_key, b"ACCES REFUSE"))
            return
            
        # 3. Phase 2: Transfert de Données (EtM)
        
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            try:
                plaintext = decrypt_message(enc_key, mac_key, data)
                logger.info(f"Message reçu : {plaintext.decode()}")
                
                response = b"ACK : message recu et authentifie."
                encrypted_response = encrypt_message(enc_key, mac_key, response)
                conn.sendall(encrypted_response)
            except ValueError as e:
                logger.error(f"Erreur de sécurité : MAC invalide - paquet rejeté")
                # Ligne pour simuler une tentative d'exploit SOC via un log
                logger.warning(f"Tentative suspecte (payload potentiellement malveillant)")
                break
    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
    finally:
        conn.close()
        server.close()

if __name__ == "__main__":
    start_server()
