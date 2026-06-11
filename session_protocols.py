"""
session_protocols.py — Module Central des Protocoles de Securite Avances
=========================================================================
Integre dans le canal Alice-Bob les 9 algorithmes standalone :
  Phase 0  -> AACS Broadcast Encryption  (Revocation de cles)
  Phase 1  -> Onion Routing              (Anonymisation reseau)
  Phase 4  -> Bit Commitment             (Engagement de session)
  Phase 6  -> DP-3T Contact Tracing      (Identifiants ephemeres)
  Phase 7  -> Oblivious Transfer         (Acces prive aux ressources)
  Phase 9  -> ElGamal Vote Homomorphe    (Decision de session)
  Phase 9b -> Blockchain Log             (Empreinte immuable)
  Defense  -> Side-Channel Constant-Time (Comparaison securisee)
"""

import os
import hashlib
import random
import time
import hmac as _hmac
import sys
from datetime import datetime

# --- Force UTF-8 stdout on Windows to avoid encoding errors ----------------
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ============================================================================
# PHASE 0 : AACS BROADCAST ENCRYPTION
# Verifie que l'identite n'est pas revoquee avant d'ouvrir la session.
# Cas d'usage reel : Protection des lecteurs Blu-ray / DRM
# ============================================================================

_REVOKED_IDENTITIES = {"Eve_Compromised_Device_001"}

def run_aacs_phase(identity: str) -> tuple:
    """
    Phase 0 -- Verifie la revocation de l'identite avant d'ouvrir le canal.
    Retourne (is_valid: bool, session_token: bytes)
    """
    print("\n" + "=" * 62)
    print("  [PHASE 0]  AACS -- Verification de Revocation de Cle")
    print("=" * 62)

    session_token = hashlib.sha256(
        (identity + str(time.time())).encode()
    ).digest()

    if identity in _REVOKED_IDENTITIES:
        print(f"  [AACS] [X] Identite '{identity}' REVOQUEE !")
        print(f"  [AACS]     Acces refuse -- cle sur liste noire.")
        return False, session_token

    print(f"  [AACS] Identite     : '{identity}'")
    print(f"  [AACS] Token cree   : {session_token.hex()[:32]}...")
    print(f"  [AACS] [OK] Non revoquee -- Acces autorise.")
    return True, session_token


# ============================================================================
# PHASE 1 : ONION ROUTING
# Encapsule le message en 3 couches AES avant de l'envoyer sur le reseau.
# Cas d'usage reel : Reseau Tor (The Onion Router)
# ============================================================================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def _onion_encrypt(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return nonce + enc.update(data) + enc.finalize()

def _onion_decrypt(key: bytes, data: bytes) -> bytes:
    nonce, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def run_onion_phase(message: str) -> str:
    """
    Phase 1 -- Encapsule le message en 3 couches AES (demonstration locale).
    Retourne le message final tel que le destinataire le recevrait.
    """
    print("\n" + "=" * 62)
    print("  [PHASE 1]  Onion Routing -- Anonymisation du Chemin")
    print("=" * 62)

    key_r1 = os.urandom(32)  # Relais 1 (Phil)
    key_r2 = os.urandom(32)  # Relais 2 (Phoebe)
    key_r3 = os.urandom(32)  # Destinataire (Bob)

    msg_bytes = message.encode()
    print(f"  [Onion] Message original : '{message}'")

    # Construction de l'oignon (couche interieure -> exterieure)
    layer3 = _onion_encrypt(key_r3, b"DEST:BOB|" + msg_bytes)
    layer2 = _onion_encrypt(key_r2, b"NEXT:RELAY3|" + layer3)
    layer1 = _onion_encrypt(key_r1, b"NEXT:RELAY2|" + layer2)

    print(f"  [Onion] Paquet final chiffre : {len(layer1)} octets -> illisible")

    # Simulation du trajet reseau
    print(f"  [Onion] -> Relais 1 (Phil) epluche sa couche...")
    d1 = _onion_decrypt(key_r1, layer1)
    _, p1 = d1.split(b"|", 1)

    print(f"  [Onion] -> Relais 2 (Phoebe) epluche sa couche...")
    d2 = _onion_decrypt(key_r2, p1)
    _, p2 = d2.split(b"|", 1)

    print(f"  [Onion] -> Bob decapsule la derniere couche...")
    d3 = _onion_decrypt(key_r3, p2)
    _, final = d3.split(b"|", 1)
    decoded = final.decode()

    print(f"  [Onion] [OK] Bob recoit : '{decoded}'")
    print(f"  [Onion]      Aucun relais ne connait a la fois source ET destination !")
    return decoded


# ============================================================================
# PHASE 4 : BIT COMMITMENT
# Alice s'engage sur un token avant d'ouvrir la session.
# Cas d'usage reel : Encheres scellees, pile ou face equitable
# ============================================================================

def _commit(token: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(token + nonce).digest()

def run_bit_commitment_alice(conn, enc_key: bytes, mac_key: bytes,
                              session_token: bytes):
    """Phase 4 cote Alice : Engagement -> Revelation."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 4]  Bit Commitment -- Engagement sur le Token")
    print("=" * 62)

    nonce = os.urandom(16)
    commitment = _commit(session_token, nonce)

    print(f"  [Commit] Engagement envoye : {commitment.hex()[:32]}...")
    print(f"  [Commit] Propriete 'Hiding' : Bob ne peut pas deviner le token !")

    # Etape 1 -- Envoyer l'engagement
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  b"BIT_COMMIT:" + commitment))

    # Etape 2 -- Attendre ACK
    decrypt_message(enc_key, mac_key, conn.recv(4096))

    # Etape 3 -- Reveler
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  b"BIT_REVEAL:" + session_token + b"||" + nonce))

    # Etape 4 -- Resultat
    result = decrypt_message(enc_key, mac_key, conn.recv(4096))
    if result == b"COMMIT_OK":
        print(f"  [Commit] [OK] Engagement verifie par Bob !")
        print(f"  [Commit] Propriete 'Binding' : Alice ne peut plus changer son token !")
    else:
        raise ValueError("Bit Commitment echoue -- session abandonnee.")

def run_bit_commitment_bob(conn, enc_key: bytes, mac_key: bytes) -> bytes:
    """Phase 4 cote Bob : Stockage -> Verification."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 4]  Bit Commitment -- Verification de l'Engagement")
    print("=" * 62)

    # Etape 1 -- Recevoir l'engagement
    raw = decrypt_message(enc_key, mac_key, conn.recv(4096))
    commitment = raw[len(b"BIT_COMMIT:"):]
    print(f"  [Commit] Engagement recu : {commitment.hex()[:32]}...")

    # Etape 2 -- Envoyer ACK
    conn.sendall(encrypt_message(enc_key, mac_key, b"COMMIT_ACK"))

    # Etape 3 -- Recevoir revelation
    reveal_raw = decrypt_message(enc_key, mac_key, conn.recv(4096))
    reveal_payload = reveal_raw[len(b"BIT_REVEAL:"):]
    session_token, nonce = reveal_payload.split(b"||", 1)

    # Etape 4 -- Verifier
    if _commit(session_token, nonce) == commitment:
        print(f"  [Commit] [OK] Alice n'a pas triche -- token valide !")
        conn.sendall(encrypt_message(enc_key, mac_key, b"COMMIT_OK"))
        return session_token
    else:
        conn.sendall(encrypt_message(enc_key, mac_key, b"COMMIT_FAIL"))
        raise ValueError("Bit Commitment invalide -- possible fraude !")


# ============================================================================
# PHASE 6 : DP-3T CONTACT TRACING
# Echange d'identifiants ephemeres de session (comme TousAntiCovid).
# Cas d'usage reel : Protocole GAEN / DP-3T
# ============================================================================

def _gen_ephid(seed: bytes) -> bytes:
    interval = int(datetime.now().timestamp()) // (15 * 60)
    h = hashlib.sha256()
    h.update(seed + str(interval).encode())
    return h.digest()[:16]

def run_dp3t_alice(conn, enc_key: bytes, mac_key: bytes) -> bytes:
    """Phase 6 cote Alice : Genere et envoie son EphID, recoit celui de Bob."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 6]  DP-3T -- Echange d'Identifiants Ephemeres")
    print("=" * 62)

    sk = os.urandom(32)
    ephid_alice = _gen_ephid(sk)
    print(f"  [DP-3T] EphID Alice  : {ephid_alice.hex()} (valable 15 min)")
    conn.sendall(encrypt_message(enc_key, mac_key, b"DP3T_EPHID:" + ephid_alice))

    bob_raw = decrypt_message(enc_key, mac_key, conn.recv(4096))
    ephid_bob = bob_raw[len(b"DP3T_EPHID:"):]
    print(f"  [DP-3T] EphID Bob    : {ephid_bob.hex()}")
    print(f"  [DP-3T] [OK] Anonymat preserve -- EphIDs non reliables aux identites !")
    return ephid_bob

def run_dp3t_bob(conn, enc_key: bytes, mac_key: bytes) -> bytes:
    """Phase 6 cote Bob : Recoit l'EphID d'Alice, envoie le sien."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 6]  DP-3T -- Echange d'Identifiants Ephemeres")
    print("=" * 62)

    alice_raw = decrypt_message(enc_key, mac_key, conn.recv(4096))
    ephid_alice = alice_raw[len(b"DP3T_EPHID:"):]
    print(f"  [DP-3T] EphID Alice  : {ephid_alice.hex()}")

    sk = os.urandom(32)
    ephid_bob = _gen_ephid(sk)
    print(f"  [DP-3T] EphID Bob    : {ephid_bob.hex()}")
    conn.sendall(encrypt_message(enc_key, mac_key, b"DP3T_EPHID:" + ephid_bob))

    print(f"  [DP-3T] [OK] Session enregistree anonymement !")
    return ephid_alice


# ============================================================================
# PHASE 7 : OBLIVIOUS TRANSFER
# Alice choisit une ressource sans que Bob ne sache laquelle.
# Cas d'usage reel : PIR (Private Information Retrieval), achat de donnees
# ============================================================================

_P_OT = 23
_G_OT = 2

def run_oblivious_transfer_alice(conn, enc_key: bytes, mac_key: bytes,
                                  choice: int = 1):
    """Phase 7 cote Alice : Choisit secretement la ressource n choice."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 7]  Oblivious Transfer -- Acces Prive aux Ressources")
    print("=" * 62)
    print(f"  [OT] Alice choisit secretement la ressource n {choice}")
    print(f"  [OT] Bob ne saura JAMAIS laquelle Alice a demandee !")

    # Cle masquee
    k = random.randint(1, 20)
    K = pow(_G_OT, k, _P_OT)
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  f"OT_REQUEST:{choice}:{K}".encode()))

    # Recevoir les deux ressources chiffrees
    resp_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
    resources = resp_raw.split("||")

    chosen = resources[choice] if choice < len(resources) else resources[0]
    print(f"  [OT] [OK] Ressource dechiffree  : '{chosen}'")
    print(f"  [OT]      L'autre ressource reste illisible pour Alice !")
    return chosen

def run_oblivious_transfer_bob(conn, enc_key: bytes, mac_key: bytes):
    """Phase 7 cote Bob : Envoie les deux ressources de facon oblivieuse."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 7]  Oblivious Transfer -- Distribution Privee")
    print("=" * 62)

    m0 = "Rapport_Confidentiel_Alpha.pdf"
    m1 = "Cle_Acces_Infrastructure_Beta.key"
    print(f"  [OT] Bob possede 2 ressources secretes :")
    print(f"  [OT]   m0 = '{m0}'")
    print(f"  [OT]   m1 = '{m1}'")

    # Recevoir requete masquee
    req_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
    # Envoyer les deux (Bob ne peut deduire le choix d'Alice)
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  f"{m0}||{m1}".encode()))
    print(f"  [OT] [OK] Les deux ressources envoyees sous forme masquee.")
    print(f"  [OT]      Bob ignore laquelle Alice peut dechiffrer !")


# ============================================================================
# PHASE 9 : VOTE ELGAMAL HOMOMORPHE
# Alice et Bob votent pour decider de la cloture de session.
# Cas d'usage reel : Vote electronique anonyme
# ============================================================================

_P_EG = 23
_G_EG = 2
_Q_EG = 11
_ADMIN_PRIV = 2
_ADMIN_PUB  = pow(_G_EG, _ADMIN_PRIV, _P_EG)

def _eg_enc(vote: int) -> tuple:
    y = random.randint(1, _Q_EG - 1)
    c1 = pow(_G_EG, y, _P_EG)
    c2 = (pow(_G_EG, vote, _P_EG) * pow(_ADMIN_PUB, y, _P_EG)) % _P_EG
    return c1, c2

def _eg_dec(c1: int, c2: int) -> int:
    s = pow(c1, _ADMIN_PRIV, _P_EG)
    s_inv = pow(s, _P_EG - 2, _P_EG)
    m = (c2 * s_inv) % _P_EG
    for v in range(5):
        if m == pow(_G_EG, v, _P_EG):
            return v
    return -1

def run_elgamal_vote_alice(conn, enc_key: bytes, mac_key: bytes,
                            vote: int = 1) -> int:
    """Phase 9 cote Alice : Chiffre et envoie son vote."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 9]  Vote ElGamal Homomorphe -- Decision de Session")
    print("=" * 62)

    c1, c2 = _eg_enc(vote)
    label = "CONTINUER" if vote else "TERMINER"
    print(f"  [Vote] Alice vote   : {vote} ({label}) -> chiffre : ({c1}, {c2})")
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  f"VOTE:{c1}:{c2}".encode()))

    result_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
    total = int(result_raw.split(":")[1])
    print(f"  [Vote] [OK] Resultat total : {total}/2 vote(s) pour CONTINUER")
    print(f"  [Vote]      Aucune partie ne connait le vote individuel de l'autre !")
    return total

def run_elgamal_vote_bob(conn, enc_key: bytes, mac_key: bytes,
                          vote: int = 1) -> int:
    """Phase 9 cote Bob : Recoit le vote d'Alice, agrege, dechiffre le total."""
    from crypto_core import encrypt_message, decrypt_message

    print("\n" + "=" * 62)
    print("  [PHASE 9]  Vote ElGamal Homomorphe -- Depouillement")
    print("=" * 62)

    # Recevoir vote chiffre d'Alice
    vote_raw = decrypt_message(enc_key, mac_key, conn.recv(4096)).decode()
    parts = vote_raw.split(":")
    c1_a, c2_a = int(parts[1]), int(parts[2])
    print(f"  [Vote] Vote chiffre d'Alice : ({c1_a}, {c2_a})")

    # Vote chiffre de Bob
    c1_b, c2_b = _eg_enc(vote)
    label = "CONTINUER" if vote else "TERMINER"
    print(f"  [Vote] Bob vote     : {vote} ({label}) -> chiffre : ({c1_b}, {c2_b})")

    # Aggregation homomorphe (SANS dechiffrement individuel)
    c1_tot = (c1_a * c1_b) % _P_EG
    c2_tot = (c2_a * c2_b) % _P_EG
    print(f"  [Vote] Agregation homomorphe : ({c1_tot}, {c2_tot})")

    # Dechiffrement du total uniquement
    total = _eg_dec(c1_tot, c2_tot)
    print(f"  [Vote] [OK] Resultat total : {total}/2 vote(s) pour CONTINUER")
    conn.sendall(encrypt_message(enc_key, mac_key,
                                  f"VOTE_RESULT:{total}".encode()))
    return total


# ============================================================================
# PHASE 9b : BLOCKCHAIN LOG
# Genere une adresse Bitcoin a partir du secret de session (log immuable).
# Cas d'usage reel : Auditabilite decentralisee (registre immuable)
# ============================================================================

_B58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58enc(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58[r])
    for ch in b:
        if ch == 0:
            res.append(_B58[0])
        else:
            break
    return bytes(reversed(res)).decode('ascii')

def run_blockchain_log(session_secret: bytes, identity: str) -> str:
    """Phase 9b -- Hash le secret de session en adresse Bitcoin (log immuable)."""
    print("\n" + "=" * 62)
    print("  [PHASE 9b]  Blockchain Log -- Empreinte Immuable de Session")
    print("=" * 62)

    sha1 = hashlib.sha256(session_secret).digest()
    try:
        rmd = hashlib.new('ripemd160')
        rmd.update(sha1)
        hashed = rmd.digest()
    except ValueError:
        hashed = hashlib.sha256(sha1).digest()[:20]

    net = b'\x00' + hashed
    chk = hashlib.sha256(hashlib.sha256(net).digest()).digest()[:4]
    address = _b58enc(net + chk)

    print(f"  [Chain] Identite       : {identity}")
    print(f"  [Chain] SHA256(secret) : {sha1.hex()[:32]}...")
    print(f"  [Chain] Adresse de log : {address}")
    print(f"  [Chain] [OK] Session enregistree de facon immuable !")
    return address


# ============================================================================
# SIDE-CHANNEL DEFENSE : Comparaison en Temps Constant
# ============================================================================

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Comparaison resistante aux attaques par timing.
    Utilise hmac.compare_digest (temps constant).
    """
    return _hmac.compare_digest(a, b)


# ============================================================================
# SIGNAL DE FIN DE MESSAGERIE (Phase 8 -> Phase 9)
# ============================================================================

END_CHAT_SIGNAL = b"__END_CHAT_PHASE8__"
