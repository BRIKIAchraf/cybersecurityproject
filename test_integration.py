"""
test_integration.py -- Test automatise du protocole complet en 9 phases.
Lance Bob et Alice dans des threads separes pour valider toutes les phases.
"""
import sys
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import socket
import threading
import time

from config import HOST, BOB_PORT
from dh_handshake import (generate_dh_private_key, get_public_bytes,
                           compute_shared_secret, sign_data, verify_signature,
                           load_public_key)
from crypto_core import derive_keys, encrypt_message, decrypt_message
from trusted_keys import (ALICE_IDENTITY_PRIV, BOB_IDENTITY_PUB_BYTES,
                           BOB_IDENTITY_PRIV, ALICE_IDENTITY_PUB_BYTES)
from zkp_schnorr import Prover, Verifier, G, P

from session_protocols import (
    run_aacs_phase, run_onion_phase,
    run_bit_commitment_alice, run_bit_commitment_bob,
    run_dp3t_alice, run_dp3t_bob,
    run_oblivious_transfer_alice, run_oblivious_transfer_bob,
    run_elgamal_vote_alice, run_elgamal_vote_bob,
    run_blockchain_log, secure_compare,
    END_CHAT_SIGNAL,
)

SECRET_ADMIN = 42
TEST_PORT = 19999  # Use a different port to avoid conflicts
results = {"alice": False, "bob": False}


def run_bob(ready_event):
    """Bob (server) thread."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', TEST_PORT))
    server.listen(1)
    ready_event.set()

    conn, addr = server.accept()
    try:
        # PHASE 0
        ok, _ = run_aacs_phase("Bob_Server_QG")
        assert ok, "AACS failed for Bob"

        # PHASE 2 - Handshake
        alice_data = b""
        while len(alice_data) < 250:
            chunk = conn.recv(4096)
            if not chunk: break
            alice_data += chunk
            if b'---SIG---' in alice_data and len(alice_data.split(b'---SIG---')[1]) > 60:
                break
        alice_pub_bytes, sig_alice = alice_data.split(b'---SIG---')
        alice_id_pub = load_public_key(ALICE_IDENTITY_PUB_BYTES)
        assert verify_signature(alice_id_pub, sig_alice, alice_pub_bytes), "Alice sig failed"
        print("  [Bob] PHASE 2 [OK] - Signature Alice verifiee")

        bob_priv = generate_dh_private_key()
        bob_pub_bytes = get_public_bytes(bob_priv)
        sig_bob = sign_data(BOB_IDENTITY_PRIV, bob_pub_bytes)
        conn.sendall(bob_pub_bytes + b'---SIG---' + sig_bob)

        # PHASE 3 - HKDF
        shared_secret = compute_shared_secret(bob_priv, alice_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        print("  [Bob] PHASE 3 [OK] - Cles derivees")

        # PHASE 4 - Bit Commitment
        run_bit_commitment_bob(conn, enc_key, mac_key)
        print("  [Bob] PHASE 4 [OK] - Commitment verifie")

        # PHASE 5 - ZKP
        admin_pub = pow(G, SECRET_ADMIN, P)
        verifier = Verifier(v=admin_pub)
        t_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
        t = int(t_raw.split(':')[1])
        c = verifier.generate_challenge(t)
        conn.sendall(encrypt_message(enc_key, mac_key, f"ZKP_C:{c}".encode()))
        g_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
        gamma = int(g_raw.split(':')[1])
        assert verifier.verify(t, gamma), "ZKP failed"
        conn.sendall(encrypt_message(enc_key, mac_key, b"ACCES ADMIN OK (ZKP)"))
        print("  [Bob] PHASE 5 [OK] - ZKP verifie")

        # PHASE 6 - DP-3T
        run_dp3t_bob(conn, enc_key, mac_key)
        print("  [Bob] PHASE 6 [OK] - EphIDs echanges")

        # PHASE 7 - OT
        run_oblivious_transfer_bob(conn, enc_key, mac_key)
        print("  [Bob] PHASE 7 [OK] - Transfert envoye")

        # PHASE 8 - Messages
        data = conn.recv(4096)
        plaintext = decrypt_message(enc_key, mac_key, data)
        if plaintext == END_CHAT_SIGNAL:
            print("  [Bob] PHASE 8 [OK] - Signal de fin recu")
        else:
            msg = plaintext.decode()
            print(f"  [Bob] PHASE 8 [OK] - Message recu : '{msg}'")
            conn.sendall(encrypt_message(enc_key, mac_key, b"Reponse auto de Bob"))
            # Wait for end signal
            data2 = conn.recv(4096)
            plaintext2 = decrypt_message(enc_key, mac_key, data2)
            print("  [Bob] PHASE 8 [OK] - Fin de chat")

        # PHASE 9 - Vote
        run_elgamal_vote_bob(conn, enc_key, mac_key, vote=1)
        print("  [Bob] PHASE 9 [OK] - Vote depouille")

        # PHASE 9b - Blockchain
        run_blockchain_log(shared_secret, "Bob_Server_QG")
        print("  [Bob] PHASE 9b [OK] - Blockchain log cree")

        results["bob"] = True
    except Exception as e:
        print(f"  [Bob] ERREUR : {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        server.close()


def run_alice(ready_event):
    """Alice (client) thread."""
    ready_event.wait()
    time.sleep(0.3)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', TEST_PORT))

    try:
        # PHASE 0
        ok, session_token = run_aacs_phase("Alice_Agent_007")
        assert ok

        # PHASE 1
        run_onion_phase("Test automatique")
        print("  [Alice] PHASE 1 [OK] - Onion routing")

        # PHASE 2 - Handshake
        alice_priv = generate_dh_private_key()
        alice_pub_bytes = get_public_bytes(alice_priv)
        sig_alice = sign_data(ALICE_IDENTITY_PRIV, alice_pub_bytes)
        client.sendall(alice_pub_bytes + b'---SIG---' + sig_alice)

        bob_response = b""
        while len(bob_response) < 250:
            chunk = client.recv(4096)
            if not chunk: break
            bob_response += chunk
            if b'---SIG---' in bob_response and len(bob_response.split(b'---SIG---')[1]) > 60:
                break
        bob_pub_bytes, sig_bob = bob_response.split(b'---SIG---')
        bob_id_pub = load_public_key(BOB_IDENTITY_PUB_BYTES)
        assert verify_signature(bob_id_pub, sig_bob, bob_pub_bytes), "Bob sig failed"
        print("  [Alice] PHASE 2 [OK] - Handshake PKI")

        # PHASE 3 - HKDF
        shared_secret = compute_shared_secret(alice_priv, bob_pub_bytes)
        enc_key, mac_key = derive_keys(shared_secret)
        print("  [Alice] PHASE 3 [OK] - HKDF cles derivees")

        # PHASE 4 - Bit Commitment
        run_bit_commitment_alice(client, enc_key, mac_key, session_token)
        print("  [Alice] PHASE 4 [OK] - Commitment accepte")

        # PHASE 5 - ZKP
        prover = Prover(alpha=SECRET_ADMIN)
        t = prover.create_commitment()
        client.sendall(encrypt_message(enc_key, mac_key, f"ZKP_T:{t}".encode()))
        c_raw = decrypt_message(enc_key, mac_key, client.recv(4096)).decode()
        c = int(c_raw.split(':')[1])
        gamma = prover.compute_response(c)
        client.sendall(encrypt_message(enc_key, mac_key, f"ZKP_GAMMA:{gamma}".encode()))
        val = decrypt_message(enc_key, mac_key, client.recv(4096)).decode()
        assert "OK" in val
        print("  [Alice] PHASE 5 [OK] - ZKP admin")

        # PHASE 6 - DP-3T
        run_dp3t_alice(client, enc_key, mac_key)
        print("  [Alice] PHASE 6 [OK] - DP-3T EphIDs")

        # PHASE 7 - OT
        run_oblivious_transfer_alice(client, enc_key, mac_key, choice=1)
        print("  [Alice] PHASE 7 [OK] - OT ressource recue")

        # PHASE 8 - End immediately (no interactive messages for this test)
        client.sendall(encrypt_message(enc_key, mac_key, END_CHAT_SIGNAL))
        print("  [Alice] PHASE 8 [OK] - Fin de chat envoyee")

        # PHASE 9 - Vote
        run_elgamal_vote_alice(client, enc_key, mac_key, vote=1)
        print("  [Alice] PHASE 9 [OK] - Vote envoye")

        # PHASE 9b - Blockchain
        run_blockchain_log(shared_secret, "Alice_Agent_007")
        print("  [Alice] PHASE 9b [OK] - Blockchain log")

        results["alice"] = True
    except Exception as e:
        print(f"  [Alice] ERREUR : {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    print("=" * 62)
    print("  TEST D'INTEGRATION -- Protocole Complet en 9 Phases")
    print("=" * 62)

    ready = threading.Event()
    bob_thread = threading.Thread(target=run_bob, args=(ready,))
    alice_thread = threading.Thread(target=run_alice, args=(ready,))

    bob_thread.start()
    alice_thread.start()

    bob_thread.join(timeout=30)
    alice_thread.join(timeout=30)

    print()
    print("=" * 62)
    if results["alice"] and results["bob"]:
        print("  [OK] TOUTES LES 9 PHASES ONT REUSSI !")
    else:
        print("  [ERREUR] Certaines phases ont echoue.")
        print(f"  Alice: {'OK' if results['alice'] else 'ERREUR'}")
        print(f"  Bob:   {'OK' if results['bob'] else 'ERREUR'}")
    print("=" * 62)
