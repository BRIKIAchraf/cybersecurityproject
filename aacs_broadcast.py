import hashlib

def kdf(key: bytes, context: str) -> bytes:
    h = hashlib.sha256()
    h.update(key + context.encode())
    return h.digest()[:16] # Clé 128 bits pour l'exemple

if __name__ == "__main__":
    print("=====================================================")
    print("--- Scénario 3 : Diffusion Révocable (Système AACS) ---")
    print("=====================================================\n")
    
    # Arbre binaire simplifié (Racine -> Nœuds -> Feuilles/Appareils)
    # Racine = K_root
    # Gauche = K_L, Droite = K_R
    # Feuilles (Appareils) : A (gauche-gauche), B (gauche-droite), C (droite-gauche), Eva (droite-droite)
    
    # État Initial
    k_root_initial = b"Racine_AACS_Originale"
    print("[*] Le serveur diffuse un film chiffré avec K_root.")
    print("[*] Alice (Appareil A), Bob (B), Charlie (C) et Eva possèdent un chemin vers K_root.\n")
    
    # Eva pirate la clé racine depuis son appareil !
    print("[!] ALERTE : L'appareil d'Eva a été compromis et mis sur liste noire !")
    print("[!] Le serveur doit révoquer K_root sans déconnecter Alice, Bob et Charlie.\n")
    
    # Processus de Révocation (Broadcast Encryption Tree)
    print("[>] Génération de la nouvelle clé racine (K_root_V2)...")
    k_root_v2 = b"Nouvelle_Racine_Secrete"
    
    print("[>] Le serveur diffuse K_root_V2 chiffrée uniquement pour les branches saines :")
    # Au lieu de chiffrer avec K_R (car Eva connait K_R puisqu'elle est sur la branche droite),
    # Le serveur chiffre avec K_L (la branche gauche, qu'Eva ne connait pas)
    # Et avec la clé directe de Charlie (qui est sur la branche droite mais pas du côté d'Eva)
    
    print("    1. Diffusion de E(K_L, K_root_V2) -> Alice et Bob (Branche gauche) peuvent déchiffrer.")
    print("    2. Diffusion de E(K_Charlie, K_root_V2) -> Charlie déchiffre directement.")
    print("    3. Eva est isolée : elle n'a ni K_L, ni K_Charlie !")
    
    print("\n[OK] Succès : Le réseau est purgé. Le nouveau film Blu-ray ne sera lisible que par A, B et C.")
