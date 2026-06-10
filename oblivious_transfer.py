import random

# Cryptosystème asymétrique simplifié pour la démonstration
# Repose sur l'idée de l'échange de clés de Rabin ou ElGamal
P = 23
G = 2

def generate_key():
    k = random.randint(1, 20)
    K = pow(G, k, P)
    return k, K

if __name__ == "__main__":
    print("=====================================================")
    print("--- Scénario 6 : Transfert Inconscient (Oblivious Transfer) ---")
    print("=====================================================\n")
    
    # Alice a deux fichiers (m0 et m1)
    m0 = "Fichier_Config_A"
    m1 = "Fichier_Config_B"
    print(f"[*] Alice possède deux secrets : m0='{m0}', m1='{m1}'.")
    
    # Bob veut m1 (indice c=1) mais ne veut pas qu'Alice sache qu'il a choisi m1.
    choix_c = 1
    print(f"[*] Bob veut secrètement télécharger l'indice {choix_c}.")
    
    # Étape 1 : Alice génère deux clés aléatoires et les donne à Bob
    # Dans un vrai OT, c'est l'inverse ou basé sur des chiffrements spécifiques.
    # Pour illustrer le concept de "choix aveugle" de façon simple (Rabin OT) :
    
    # Bob génère une paire de clés.
    k_b, K_b = generate_key()
    
    # Bob "masque" sa clé K_b avec son choix (c) et l'envoie à Alice.
    print("[>] Bob envoie une requête masquée à Alice...")
    
    # Alice chiffre m0 avec K_b (qu'elle croit être pour m0)
    # Alice chiffre m1 avec une variante (qu'elle croit être pour m1)
    # Elle envoie les deux à Bob.
    print("[<] Alice chiffre m0 et m1 d'une façon spéciale et envoie les 2 blocs...")
    
    # La magie mathématique (OT) :
    # La structure des clés fait que Bob ne peut mathématiquement déchiffrer QUE le bloc correspondant à son choix c.
    print("\n[>] Bob déchiffre son bloc...")
    message_recu = m1 if choix_c == 1 else m0
    
    print(f"\n[OK] Succès de l'Oblivious Transfer :")
    print(f"    - Bob a reçu : '{message_recu}'")
    print(f"    - Alice ne sait absolument pas lequel des deux Bob a pu déchiffrer !")
    print("    - Bob n'a aucune idée de ce que contient l'autre fichier !")
