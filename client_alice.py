import socket
import logging
import sys
from config import BOB_IP, BOB_PORT, EVE_PORT, PHASE, EVE_IP
from dh_handshake import generate_dh_private_key, get_public_bytes, compute_shared_secret, sign_data, verify_signature, load_public_key
from crypto_core import derive_keys, encrypt_message, decrypt_message
from logger_config import setup_logger
from trusted_keys import ALICE_IDENTITY_PRIV, BOB_IDENTITY_PUB_BYTES
from zkp_schnorr import Prover

logger = setup_logger('Alice')

def start_client():
    # Allow passing an argument to target Eve instead of Bob directly
    target_port = BOB_PORT
    target_ip = BOB_IP
    if len(sys.argv) > 1 and sys.argv[1] == '--eve':
        target_port = EVE_PORT
        target_ip = EVE_IP
        logger.info("Mode test: Connexion à Eve (simulation d'interception)")
        
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target_ip, target_port))
    except ConnectionRefusedError:
        logger.error(f"Impossible de se connecter à {target_ip}:{target_port}")
        return

    try:
        # 1. Phase 1: Handshake AKE (Authentifié)
        alice_priv = generate_dh_private_key()
        alice_pub_bytes = get_public_bytes(alice_priv)
        
        # Alice signe sa clé éphémère DH
        signature_alice = sign_data(ALICE_IDENTITY_PRIV, alice_pub_bytes)
        client.sendall(alice_pub_bytes + b'---SIG---' + signature_alice)
        
        # Bob répond avec sa clé et sa signature
        bob_response = b""
        while len(bob_response) < 250:
            chunk = client.recv(4096)
            if not chunk: break
            bob_response += chunk
            if b'---SIG---' in bob_response and len(bob_response.split(b'---SIG---')[1]) > 60:
                break
                
        if b'---SIG---' not in bob_response:
            logger.error("Format de réponse invalide de Bob.")
            return
            
        bob_pub_bytes, signature_bob = bob_response.split(b'---SIG---')
        
        # Vérification de la signature de Bob (Défense MITM)
        bob_id_pub = load_public_key(BOB_IDENTITY_PUB_BYTES)
        if not verify_signature(bob_id_pub, signature_bob, bob_pub_bytes):
            logger.error("[AKE CRITIQUE] Signature de Bob invalide ! MITM Détecté.")
            return
            
        logger.info("Signature de Bob vérifiée. Certificat valide.")
        
        shared_secret = compute_shared_secret(alice_priv, bob_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        logger.info("Clés dérivées. Canal sécurisé établi.")

        # 2. Phase 3: ZKP Administrateur
        secret_admin = 42
        alice_prover = Prover(alpha=secret_admin)
        
        # Etape 1: Engagement
        t = alice_prover.create_commitment()
        client.sendall(encrypt_message(enc_key, mac_key, f"ZKP_T:{t}".encode()))
        
        # Etape 2: Défi de Bob
        defi_data = client.recv(4096)
        defi_str = decrypt_message(enc_key, mac_key, defi_data).decode()
        c = int(defi_str.split(':')[1])
        
        # Etape 3: Réponse
        gamma = alice_prover.compute_response(c)
        client.sendall(encrypt_message(enc_key, mac_key, f"ZKP_GAMMA:{gamma}".encode()))
        
        # Validation
        val_data = client.recv(4096)
        val_msg = decrypt_message(enc_key, mac_key, val_data).decode()
        logger.info(f"Résultat de l'accès Admin (ZKP) : {val_msg}")

        # 3. Phase 2: Transfert de Données (EtM)
        logger.info("Canal prêt. Tapez 'quit' pour quitter.")
        
        while True:
            msg_str = input("\n[Vous/Alice] Entrez un message: ")
            if msg_str.lower() == 'quit':
                break
                
            message = msg_str.encode('utf-8')
            encrypted_msg = encrypt_message(enc_key, mac_key, message)
            client.sendall(encrypted_msg)
            
            data = client.recv(4096)
            if data:
                try:
                    plaintext = decrypt_message(enc_key, mac_key, data)
                    logger.info(f"Réponse de Bob : {plaintext.decode()}")
                except ValueError as e:
                    logger.error(f"Erreur de sécurité sur la réponse : {e}")
    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()
