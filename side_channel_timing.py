import time
import hmac
import timeit

SECRET_PASSWORD = b"SUPER_SECRET_TOKEN"

def weak_string_compare(val1: bytes, val2: bytes) -> bool:
    """Comparaison vulnérable : s'arrête au premier caractère faux."""
    if len(val1) != len(val2): return False
    for i in range(len(val1)):
        if val1[i] != val2[i]:
            return False
        # Simuler une légère latence pour la démonstration du Side-Channel
        time.sleep(0.001)
    return True

def secure_string_compare(val1: bytes, val2: bytes) -> bool:
    """Comparaison en Temps Constant : ne fuit aucune information (hmac.compare_digest)."""
    return hmac.compare_digest(val1, val2)

def simulate_timing_attack(compare_func):
    """L'attaquant mesure le temps pour deviner le premier caractère."""
    # On teste le premier caractère en gardant les autres faux
    guess_wrong = b"A" + b"_" * (len(SECRET_PASSWORD) - 1)
    guess_right = SECRET_PASSWORD[0:1] + b"_" * (len(SECRET_PASSWORD) - 1)
    
    t_wrong = timeit.timeit(lambda: compare_func(SECRET_PASSWORD, guess_wrong), number=50)
    t_right = timeit.timeit(lambda: compare_func(SECRET_PASSWORD, guess_right), number=50)
    
    return t_wrong, t_right

if __name__ == "__main__":
    print("=====================================================")
    print("--- Scénario 5 : Attaque par Canal Auxiliaire (Timing) ---")
    print("=====================================================\n")
    
    print("[!] Eva teste une comparaison classique (Faible)...")
    t_w, t_r = simulate_timing_attack(weak_string_compare)
    diff = t_r - t_w
    print(f"    Temps (Mauvaise lettre) : {t_w:.4f}s")
    print(f"    Temps (Bonne lettre)    : {t_r:.4f}s")
    print(f"    => Différence (Fuite)   : {diff:.4f}s")
    if diff > 0.01:
        print("    [ERREUR] VULNÉRABLE : Eva sait que la 1ère lettre est bonne car le serveur a mis plus de temps à répondre !")
        
    print("\n[!] Alice met à jour le code vers un temps constant (Fort)...")
    t_w2, t_r2 = simulate_timing_attack(secure_string_compare)
    diff2 = t_r2 - t_w2
    print(f"    Temps (Mauvaise lettre) : {t_w2:.4f}s")
    print(f"    Temps (Bonne lettre)    : {t_r2:.4f}s")
    print(f"    => Différence (Fuite)   : {diff2:.4f}s")
    if abs(diff2) < 0.01:
        print("    [OK] SÉCURISÉ : Aucune différence de temps. Eva ne peut rien deviner.")
