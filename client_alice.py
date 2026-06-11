"""
client_alice.py -- Agent Alice (Protocole Complet en 9 Phases)
==============================================================
Protocole de session :
  Phase 0  -> AACS       : Verification de revocation
  Phase 1  -> Onion      : Anonymisation reseau (demonstration)
  Phase 2  -> ECDH+PKI   : Handshake authentifie (Anti-MitM)
  Phase 3  -> HKDF       : Derivation des cles
  Phase 4  -> BitCommit  : Engagement sur le token de session
  Phase 5  -> ZKP Schnorr: Authentification Admin (Zero Connaissance)
  Phase 6  -> DP-3T      : Echange d'identifiants ephemeres
  Phase 7  -> OT         : Acces prive aux ressources de Bob
  Phase 8  -> AES+HMAC   : Canal de messagerie chiffre (EtM)
  Phase 9  -> ElGamal    : Vote homomorphe de cloture de session
  Phase 9b -> Blockchain : Log immuable de la session
"""

import socket
import sys

# --- Force UTF-8 stdout on Windows ----------------------------------------
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from config import BOB_IP, BOB_PORT, EVE_PORT, EVE_IP
from dh_handshake import (generate_dh_private_key, get_public_bytes,
                           compute_shared_secret, sign_data, verify_signature,
                           load_public_key)
from crypto_core import derive_keys, encrypt_message, decrypt_message
from logger_config import setup_logger
from trusted_keys import ALICE_IDENTITY_PRIV, BOB_IDENTITY_PUB_BYTES
from zkp_schnorr import Prover

from session_protocols import (
    run_aacs_phase,
    run_onion_phase,
    run_bit_commitment_alice,
    run_dp3t_alice,
    run_oblivious_transfer_alice,
    run_elgamal_vote_alice,
    run_blockchain_log,
    END_CHAT_SIGNAL,
)

logger = setup_logger('Alice')

# --- Secret administrateur partage (connu d'Alice et de Bob) ----------------
SECRET_ADMIN = 42


def start_client():
    # ==================================================================
    # PHASE 0 -- AACS : Verification de revocation AVANT la connexion
    # ==================================================================
    is_valid, session_token = run_aacs_phase("Alice_Agent_007")
    if not is_valid:
        logger.error("[AACS] Identite revoquee -- connexion annulee.")
        return

    # ==================================================================
    # PHASE 1 -- ONION ROUTING : Demonstration locale de l'anonymisation
    # ==================================================================
    run_onion_phase("Requete initiale vers le QG de Bob")

    # -- Choix de la cible (Bob direct ou via Eve pour les tests) -------
    target_ip   = BOB_IP
    target_port = BOB_PORT
    if len(sys.argv) > 1 and sys.argv[1] == '--eve':
        target_ip   = EVE_IP
        target_port = EVE_PORT
        logger.info("Mode attaque : connexion routee via Eve (interception).")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target_ip, target_port))
        logger.info(f"Connecte a {target_ip}:{target_port}")
    except ConnectionRefusedError:
        logger.error(f"Impossible de se connecter a {target_ip}:{target_port}")
        return

    try:
        # ==============================================================
        # PHASE 2 -- ECDH + PKI/ECDSA : Handshake authentifie
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 2]  ECDH + PKI -- Handshake Authentifie")
        print("=" * 62)

        alice_priv      = generate_dh_private_key()
        alice_pub_bytes = get_public_bytes(alice_priv)
        sig_alice       = sign_data(ALICE_IDENTITY_PRIV, alice_pub_bytes)
        client.sendall(alice_pub_bytes + b'---SIG---' + sig_alice)
        print("  [ECDH] Cle publique ECDH + signature ECDSA envoyees a Bob.")

        # Reception de la reponse de Bob
        bob_response = b""
        while len(bob_response) < 250:
            chunk = client.recv(4096)
            if not chunk:
                break
            bob_response += chunk
            if (b'---SIG---' in bob_response and
                    len(bob_response.split(b'---SIG---')[1]) > 60):
                break

        if b'---SIG---' not in bob_response:
            logger.error("Format de reponse invalide de Bob.")
            return

        bob_pub_bytes, sig_bob = bob_response.split(b'---SIG---')

        # Verification de la signature de Bob (defense contre MitM)
        bob_id_pub = load_public_key(BOB_IDENTITY_PUB_BYTES)
        if not verify_signature(bob_id_pub, sig_bob, bob_pub_bytes):
            logger.error("[PKI CRITIQUE] Signature de Bob invalide -- MitM detecte !")
            return
        print("  [PKI]  [OK] Signature de Bob verifiee -- identite authentique.")

        # ==============================================================
        # PHASE 3 -- HKDF : Derivation des deux cles (AES + HMAC)
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 3]  HKDF -- Derivation des Cles de Session")
        print("=" * 62)
        shared_secret = compute_shared_secret(alice_priv, bob_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        print(f"  [HKDF] Secret partage ECDH -> 64 octets via HKDF-SHA256")
        print(f"  [HKDF] enc_key (AES-256) : {enc_key.hex()[:20]}...")
        print(f"  [HKDF] mac_key (HMAC)    : {mac_key.hex()[:20]}...")
        print(f"  [HKDF] [OK] Canal securise etabli. Confidentialite garantie.")

        # ==============================================================
        # PHASE 4 -- BIT COMMITMENT : Engagement sur le token de session
        # ==============================================================
        run_bit_commitment_alice(client, enc_key, mac_key, session_token)

        # ==============================================================
        # PHASE 5 -- ZKP SCHNORR : Authentification admin
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 5]  ZKP Schnorr -- Preuve a Divulgation Nulle")
        print("=" * 62)
        print(f"  [ZKP] Alice prouve qu'elle connait le secret {SECRET_ADMIN}")
        print(f"  [ZKP] ... sans jamais envoyer ce secret sur le reseau !")

        prover = Prover(alpha=SECRET_ADMIN)

        t = prover.create_commitment()
        client.sendall(encrypt_message(enc_key, mac_key,
                                       f"ZKP_T:{t}".encode()))
        print(f"  [ZKP] Etape 1 -- Engagement t = {t} envoye a Bob.")

        c_raw = decrypt_message(enc_key, mac_key, client.recv(4096)).decode()
        c = int(c_raw.split(':')[1])
        print(f"  [ZKP] Etape 2 -- Defi de Bob   : c = {c}")

        gamma = prover.compute_response(c)
        client.sendall(encrypt_message(enc_key, mac_key,
                                       f"ZKP_GAMMA:{gamma}".encode()))
        print(f"  [ZKP] Etape 3 -- Reponse       : gamma = {gamma} (secret non divulgue)")

        val_raw = decrypt_message(enc_key, mac_key, client.recv(4096)).decode()
        print(f"  [ZKP] [OK] Resultat : {val_raw}")

        if "REFUSE" in val_raw:
            logger.error("[ZKP] Acces admin refuse -- session terminee.")
            return

        # ==============================================================
        # PHASE 6 -- DP-3T : Echange d'identifiants ephemeres
        # ==============================================================
        run_dp3t_alice(client, enc_key, mac_key)

        # ==============================================================
        # PHASE 7 -- OBLIVIOUS TRANSFER : Acces prive aux ressources
        # ==============================================================
        run_oblivious_transfer_alice(client, enc_key, mac_key, choice=1)

        # ==============================================================
        # PHASE 8 -- AES + HMAC (EtM) : Canal de messagerie chiffre
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 8]  AES-CTR + HMAC-SHA256 -- Messagerie Securisee")
        print("=" * 62)
        print("  Canal pret. Tapez vos messages. ('quit' pour terminer)")

        while True:
            msg_str = input("\n  [Alice -> Bob] Votre message : ")
            if msg_str.lower() == 'quit':
                # Send end-of-chat signal to Bob so he exits his loop too
                client.sendall(encrypt_message(enc_key, mac_key,
                                                END_CHAT_SIGNAL))
                break

            encrypted = encrypt_message(enc_key, mac_key,
                                         msg_str.encode('utf-8'))
            client.sendall(encrypted)
            print(f"  [AES]  Envoye chiffre ({len(encrypted)} octets sur le reseau)")

            data = client.recv(4096)
            if data:
                try:
                    plaintext = decrypt_message(enc_key, mac_key, data)
                    print(f"  [Bob -> Alice] {plaintext.decode()}")
                except ValueError as e:
                    logger.error(f"Securite : {e}")

        # ==============================================================
        # PHASE 9 -- VOTE ELGAMAL : Decision homomorphe de cloture
        # ==============================================================
        run_elgamal_vote_alice(client, enc_key, mac_key, vote=1)

        # ==============================================================
        # PHASE 9b -- BLOCKCHAIN LOG : Empreinte immuable de la session
        # ==============================================================
        run_blockchain_log(shared_secret, "Alice_Agent_007")

        print("\n" + "=" * 62)
        print("  [OK] Session complete -- Toutes les phases executees avec succes !")
        print("=" * 62 + "\n")

    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
    finally:
        client.close()


if __name__ == "__main__":
    start_client()
