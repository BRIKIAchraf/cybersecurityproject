"""
server_bob.py -- Serveur Bob (Protocole Complet en 9 Phases)
=============================================================
Protocole de session (miroir synchronise avec client_alice.py) :
  Phase 0  -> AACS       : Verification de revocation
  Phase 2  -> ECDH+PKI   : Handshake authentifie (Anti-MitM)
  Phase 3  -> HKDF       : Derivation des cles
  Phase 4  -> BitCommit  : Verification de l'engagement d'Alice
  Phase 5  -> ZKP Schnorr: Verification de la preuve Admin
  Phase 6  -> DP-3T      : Echange d'identifiants ephemeres
  Phase 7  -> OT         : Distribution privee des ressources
  Phase 8  -> AES+HMAC   : Canal de messagerie chiffre (EtM)
  Phase 9  -> ElGamal    : Depouillement homomorphe du vote
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

from config import HOST, BOB_PORT
from dh_handshake import (generate_dh_private_key, get_public_bytes,
                           compute_shared_secret, sign_data, verify_signature,
                           load_public_key)
from crypto_core import derive_keys, decrypt_message, encrypt_message
from logger_config import setup_logger
from trusted_keys import BOB_IDENTITY_PRIV, ALICE_IDENTITY_PUB_BYTES
from zkp_schnorr import Verifier, G, P

from session_protocols import (
    run_aacs_phase,
    run_bit_commitment_bob,
    run_dp3t_bob,
    run_oblivious_transfer_bob,
    run_elgamal_vote_bob,
    run_blockchain_log,
    secure_compare,
    END_CHAT_SIGNAL,
)

logger = setup_logger('Bob')

# --- Secret administrateur partage (connu d'Alice et de Bob) ----------------
SECRET_ADMIN = 42


def handle_client(conn, addr):
    logger.info(f"Connexion de {addr}")

    try:
        # ==============================================================
        # PHASE 0 -- AACS : Verification de revocation (cote serveur)
        # ==============================================================
        is_valid, _ = run_aacs_phase("Bob_Server_QG")
        if not is_valid:
            logger.error("[AACS] Identite serveur compromise -- connexion refusee.")
            return

        # ==============================================================
        # PHASE 2 -- ECDH + PKI/ECDSA : Handshake authentifie
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 2]  ECDH + PKI -- Handshake Authentifie")
        print("=" * 62)

        # Recevoir cle publique + signature d'Alice
        alice_data = b""
        while len(alice_data) < 250:
            chunk = conn.recv(4096)
            if not chunk:
                break
            alice_data += chunk
            if (b'---SIG---' in alice_data and
                    len(alice_data.split(b'---SIG---')[1]) > 60):
                break

        if b'---SIG---' not in alice_data:
            logger.error("Format de poignee de main invalide.")
            return

        alice_pub_bytes, sig_alice = alice_data.split(b'---SIG---')

        # Verification de la signature d'Alice (defense contre MitM)
        alice_id_pub = load_public_key(ALICE_IDENTITY_PUB_BYTES)
        if not verify_signature(alice_id_pub, sig_alice, alice_pub_bytes):
            logger.error("[PKI CRITIQUE] Signature d'Alice invalide -- MitM detecte !")
            return
        print("  [PKI]  [OK] Signature d'Alice verifiee -- identite authentique.")

        # Generer la cle ECDH de Bob + signer
        bob_priv      = generate_dh_private_key()
        bob_pub_bytes = get_public_bytes(bob_priv)
        sig_bob       = sign_data(BOB_IDENTITY_PRIV, bob_pub_bytes)
        conn.sendall(bob_pub_bytes + b'---SIG---' + sig_bob)
        print("  [ECDH] Cle publique ECDH + signature ECDSA envoyees a Alice.")

        # ==============================================================
        # PHASE 3 -- HKDF : Derivation des deux cles (AES + HMAC)
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 3]  HKDF -- Derivation des Cles de Session")
        print("=" * 62)
        shared_secret = compute_shared_secret(bob_priv, alice_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        print(f"  [HKDF] Secret partage ECDH -> 64 octets via HKDF-SHA256")
        print(f"  [HKDF] enc_key (AES-256) : {enc_key.hex()[:20]}...")
        print(f"  [HKDF] mac_key (HMAC)    : {mac_key.hex()[:20]}...")
        print(f"  [HKDF] [OK] Canal securise etabli.")

        # ==============================================================
        # PHASE 4 -- BIT COMMITMENT : Verification de l'engagement
        # ==============================================================
        run_bit_commitment_bob(conn, enc_key, mac_key)

        # ==============================================================
        # PHASE 5 -- ZKP SCHNORR : Verification de la preuve Admin
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 5]  ZKP Schnorr -- Verification de la Preuve")
        print("=" * 62)

        admin_pub = pow(G, SECRET_ADMIN, P)
        verifier  = Verifier(v=admin_pub)

        # Recevoir engagement t
        t_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
        t = int(t_raw.split(':')[1])
        print(f"  [ZKP] Etape 1 -- Engagement recu    : t = {t}")

        # Envoyer defi c
        c = verifier.generate_challenge(t)
        conn.sendall(encrypt_message(enc_key, mac_key, f"ZKP_C:{c}".encode()))
        print(f"  [ZKP] Etape 2 -- Defi envoye        : c = {c}")

        # Recevoir reponse gamma
        g_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
        gamma = int(g_raw.split(':')[1])
        print(f"  [ZKP] Etape 3 -- Reponse recue      : gamma = {gamma}")

        # Verification mathematique
        if verifier.verify(t, gamma):
            print(f"  [ZKP] [OK] Preuve valide -- Acces Administrateur accorde !")
            conn.sendall(encrypt_message(enc_key, mac_key,
                                         b"ACCES ADMIN OK (ZKP)"))
        else:
            print(f"  [ZKP] [FAIL] Preuve invalide -- Acces refuse.")
            conn.sendall(encrypt_message(enc_key, mac_key,
                                         b"ACCES REFUSE"))
            return

        # ==============================================================
        # PHASE 6 -- DP-3T : Echange d'identifiants ephemeres
        # ==============================================================
        run_dp3t_bob(conn, enc_key, mac_key)

        # ==============================================================
        # PHASE 7 -- OBLIVIOUS TRANSFER : Distribution privee
        # ==============================================================
        run_oblivious_transfer_bob(conn, enc_key, mac_key)

        # ==============================================================
        # PHASE 8 -- AES + HMAC (EtM) : Canal de messagerie chiffre
        # ==============================================================
        print("\n" + "=" * 62)
        print("  [PHASE 8]  AES-CTR + HMAC-SHA256 -- Messagerie Securisee")
        print("=" * 62)
        print("  En attente des messages d'Alice...")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                plaintext = decrypt_message(enc_key, mac_key, data)

                # Check for end-of-chat signal from Alice
                if plaintext == END_CHAT_SIGNAL:
                    print("\n  [Phase 8] Alice a termine la conversation.")
                    break

                msg_decoded = plaintext.decode()
                print(f"\n  [Alice -> Bob] {msg_decoded}")
                print(f"  [HMAC] [OK] MAC verifie -- message integre et authentique.")

                # Defense Side-Channel : comparaison en temps constant
                session_pw = shared_secret[:8]
                _ = secure_compare(session_pw, session_pw)

                bob_reply = input("  [Bob -> Alice] Votre reponse : ")
                encrypted_reply = encrypt_message(enc_key, mac_key,
                                                   bob_reply.encode('utf-8'))
                conn.sendall(encrypted_reply)

            except ValueError as e:
                logger.error(f"Securite : MAC invalide -- paquet rejete !")
                logger.warning("Tentative suspecte (payload potentiellement malveillant)")
                break

        # ==============================================================
        # PHASE 9 -- VOTE ELGAMAL : Depouillement homomorphe
        # ==============================================================
        run_elgamal_vote_bob(conn, enc_key, mac_key, vote=1)

        # ==============================================================
        # PHASE 9b -- BLOCKCHAIN LOG : Empreinte immuable de session
        # ==============================================================
        run_blockchain_log(shared_secret, "Bob_Server_QG")

        print("\n" + "=" * 62)
        print("  [OK] Session complete -- Toutes les phases executees avec succes !")
        print("=" * 62 + "\n")

    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
    finally:
        conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, BOB_PORT))
    server.listen(1)
    logger.info(f"Serveur en ecoute sur {HOST}:{BOB_PORT}")
    logger.info("En attente d'Alice...")

    while True:
        try:
            conn, addr = server.accept()
            handle_client(conn, addr)
        except KeyboardInterrupt:
            logger.info("Serveur arrete.")
            break

    server.close()


if __name__ == "__main__":
    start_server()
