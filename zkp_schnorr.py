import os
import hashlib

# Paramètres du groupe (exemple simplifié pour la démonstration)
# En pratique, on utiliserait une courbe elliptique (comme secp256k1) ou un groupe multiplicatif de corps fini de grande taille.
# Ici on utilise des petits nombres pour illustrer le concept mathématique.
P = 23  # Modulo (premier)
G = 2   # Générateur d'ordre Q
Q = 11  # Ordre du sous-groupe (p-1)/2

def hash_to_int(*args):
    """Fonction de hachage qui retourne un entier."""
    h = hashlib.sha256()
    for arg in args:
        h.update(str(arg).encode())
    return int.from_bytes(h.digest(), 'big')

class Prover:
    """Alice (Prover) - veut prouver qu'elle connait le secret `alpha` sans le révéler."""
    def __init__(self, alpha: int):
        self.alpha = alpha  # Secret
        self.v = pow(G, alpha, P)  # Clé publique: v = g^alpha mod p
        self._beta = None

    def create_commitment(self) -> int:
        """Étape 1: Engagement (t = g^beta mod p)"""
        self._beta = int.from_bytes(os.urandom(4), 'big') % Q
        t = pow(G, self._beta, P)
        return t

    def compute_response(self, c: int) -> int:
        """Étape 3: Réponse (gamma = beta + alpha * c mod q)"""
        gamma = (self._beta + self.alpha * c) % Q
        return gamma

class Verifier:
    """Bob (Verifier) - vérifie la preuve de connaissance de Alice."""
    def __init__(self, v: int):
        self.v = v  # Clé publique d'Alice

    def generate_challenge(self, t: int) -> int:
        """Étape 2: Défi (c)"""
        # Dans la version interactive, c est aléatoire.
        # Dans la version non-interactive (Fiat-Shamir), c = H(G, v, t)
        self.c = int.from_bytes(os.urandom(4), 'big') % Q
        return self.c

    def verify(self, t: int, gamma: int) -> bool:
        """Étape 4: Vérification (g^gamma == t * v^c mod p)"""
        left = pow(G, gamma, P)
        right = (t * pow(self.v, self.c, P)) % P
        return left == right

# Test du protocole
if __name__ == "__main__":
    print("--- Protocole d'identification de Schnorr (Sigma Protocole) ---")
    secret_alpha = 7
    
    alice = Prover(alpha=secret_alpha)
    bob = Verifier(v=alice.v)
    
    # 1. Alice s'engage
    t = alice.create_commitment()
    print(f"1. Alice s'engage avec t = {t}")
    
    # 2. Bob lance un défi
    c = bob.generate_challenge(t)
    print(f"2. Bob lance le défi c = {c}")
    
    # 3. Alice répond
    gamma = alice.compute_response(c)
    print(f"3. Alice répond avec gamma = {gamma}")
    
    # 4. Bob vérifie
    is_valid = bob.verify(t, gamma)
    print(f"4. Vérification par Bob : {'RÉUSSIE (Alice est authentifiée)' if is_valid else 'ÉCHOUÉE'}")
