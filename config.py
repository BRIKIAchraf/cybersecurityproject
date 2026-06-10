# config.py — changez SEULEMENT ce fichier entre les phases

PHASE = 2   # ← mettez 1, 2 ou 3

if PHASE == 1:
    BOB_IP   = '127.0.0.1'
    BOB_PORT = 9999
    EVE_PORT = 9998
    HOST     = '127.0.0.1'
elif PHASE == 2:
    # --- CONFIGURATION RÉSEAU ---
    BOB_IP   = '192.168.x.10'  # <-- METTRE L'IP DU PC DE VOTRE AMIE (Serveur)
    EVE_IP   = '192.168.x.11'  # <-- METTRE L'IP DE LA MACHINE KALI (Attaquant)
    BOB_PORT = 9999
    EVE_PORT = 9998
    HOST     = '0.0.0.0'
elif PHASE == 3:
    BOB_IP   = '10.200.0.2'
    BOB_PORT = 9999
    EVE_PORT = 9998
    HOST     = '0.0.0.0'
