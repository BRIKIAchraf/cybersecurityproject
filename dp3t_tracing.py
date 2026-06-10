import os
import hashlib
from datetime import datetime, timedelta

def generate_ephid(seed: bytes, time_interval: int) -> bytes:
    """Génère un Identifiant Éphémère (EphID) selon le protocole DP3T (Decentralized Privacy-Preserving Proximity Tracing)."""
    # EphID = PRF(SK, time_interval)
    h = hashlib.sha256()
    h.update(seed + str(time_interval).encode())
    return h.digest()[:16] # On ne diffuse que les 16 premiers octets

if __name__ == "__main__":
    print("==========================================================")
    print("--- Module 6 : Contact Tracing (Protocole DP3T EphID)    ---")
    print("==========================================================\n")
    
    # Clé secrète quotidienne (SK), générée aléatoirement chaque jour sur l'appareil
    secret_key = os.urandom(32)
    print("[*] Clé secrète quotidienne générée sur le smartphone.")
    
    # Moment actuel
    current_time = datetime.now()
    interval = int(current_time.timestamp()) // (15 * 60) # Intervalles de 15 minutes (Epochs)
    
    ephid_1 = generate_ephid(secret_key, interval)
    print(f"[{current_time.strftime('%H:%M:%S')}] Diffusion Bluetooth (BLE) de l'EphID : {ephid_1.hex()}")
    
    # Simulation d'un saut de temps de 15 minutes
    print("\n... 15 minutes plus tard, rotation de l'identifiant pour empêcher le tracking ...\n")
    
    future_time = current_time + timedelta(minutes=15)
    interval_future = int(future_time.timestamp()) // (15 * 60)
    
    ephid_2 = generate_ephid(secret_key, interval_future)
    print(f"[{future_time.strftime('%H:%M:%S')}] Nouveau EphID généré et diffusé : {ephid_2.hex()}")
    
    print("\n=> Anonymat préservé : Impossible de lier les deux identifiants sans la clé secrète !")
