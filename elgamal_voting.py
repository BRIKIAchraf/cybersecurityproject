import random

# Paramètres du groupe (Simplifiés pour l'exemple mathématique)
P = 23
G = 2
Q = 11

def generate_keypair():
    # Clé privée a, Clé publique h = G^a
    a = random.randint(1, Q-1)
    h = pow(G, a, P)
    return a, h

def elgamal_encrypt(public_key, vote):
    # Vote doit être g^v (Homomorphie additive transformée en multiplicative)
    # v = 0 -> g^0 = 1
    # v = 1 -> g^1 = G
    message_point = pow(G, vote, P)
    
    y = random.randint(1, Q-1)
    c1 = pow(G, y, P)
    c2 = (message_point * pow(public_key, y, P)) % P
    return c1, c2

def elgamal_decrypt(private_key, c1, c2):
    # m = c2 / (c1^a)
    s = pow(c1, private_key, P)
    s_inv = pow(s, P-2, P) # Inverse modulaire (Fermat)
    message_point = (c2 * s_inv) % P
    
    # Trouver le log discret (facile car le résultat est petit: 0, 1, 2, 3...)
    if message_point == 1: return 0
    if message_point == G: return 1
    if message_point == pow(G, 2, P): return 2
    if message_point == pow(G, 3, P): return 3
    return -1 # Erreur

if __name__ == "__main__":
    print("=====================================================")
    print("--- Scénario 4 : Vote Électronique (Homomorphie ElGamal) ---")
    print("=====================================================\n")
    
    print("[*] Génération de la clé maître du serveur central de dépouillement...")
    priv_admin, pub_admin = generate_keypair()
    
    # Vote des serveurs (1 = OUI, 0 = NON)
    vote_serveur1 = 1
    vote_serveur2 = 1
    vote_serveur3 = 0
    
    print(f"[*] Chiffrement homomorphe des votes en cours : {vote_serveur1}, {vote_serveur2}, {vote_serveur3}...")
    c1_1, c2_1 = elgamal_encrypt(pub_admin, vote_serveur1)
    c1_2, c2_2 = elgamal_encrypt(pub_admin, vote_serveur2)
    c1_3, c2_3 = elgamal_encrypt(pub_admin, vote_serveur3)
    
    print(f"    S1 envoie : ({c1_1}, {c2_1})")
    print(f"    S2 envoie : ({c1_2}, {c2_2})")
    print(f"    S3 envoie : ({c1_3}, {c2_3})\n")
    
    # Dépouillement à l'aveugle (Propriété Homomorphe)
    print("[>] Agrégation des votes chiffrés SANS les déchiffrer (V_total = produit des v_i)")
    c1_total = (c1_1 * c1_2 * c1_3) % P
    c2_total = (c2_1 * c2_2 * c2_3) % P
    print(f"[>] Somme chiffrée totale : ({c1_total}, {c2_total})")
    
    # Déchiffrement du résultat final
    resultat = elgamal_decrypt(priv_admin, c1_total, c2_total)
    print(f"\n[OK] Succès : Le résultat déchiffré est {resultat} OUI.")
    print("    (Le serveur central ne sait pas qui a voté quoi, et personne ne connait les votes individuels !)")
