import os
import hashlib

def commit(message: str, nonce: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(message.encode() + nonce)
    return h.digest()

if __name__ == "__main__":
    print("==================================================")
    print("--- Scénario 2 : Enchère Scellée (Bit Commitment) ---")
    print("==================================================\n")
    
    offre_alice = "15000" # Alice veut miser 15000
    nonce_alice = os.urandom(16) # Le secret qui rend l'engagement Hiding (Caché)
    
    print(f"[*] Alice veut miser {offre_alice}€ secrètement.")
    
    # 1. Phase d'Engagement
    engagement = commit(offre_alice, nonce_alice)
    print(f"[>] Alice envoie l'engagement à Bob : {engagement.hex()}")
    print("    (Bob ne peut pas déduire l'offre à partir du hash - Propriété 'Hiding')\n")
    
    # 2. Phase de Révélation
    print("[*] Les enchères sont closes. Alice révèle son offre et son nonce.")
    print(f"[<] Alice envoie (Offre: {offre_alice}, Nonce: {nonce_alice.hex()})")
    
    # 3. Vérification par Bob
    verification = commit(offre_alice, nonce_alice)
    
    if verification == engagement:
        print("\n[OK] Succès : L'engagement correspond ! L'offre de 15000€ est validée.")
        print("    (Alice n'a pas pu changer son offre après coup grâce à la propriété 'Binding')")
    else:
        print("\n[ERREUR] Fraude : L'engagement ne correspond pas !")
