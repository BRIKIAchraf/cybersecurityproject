import time
import re
import os

LOG_FILE = "sentinelle_soc.log"

def start_soc():
    print("==================================================")
    print("--- Module 7 : SIEM SOC (Blue Team Monitoring) ---")
    print("==================================================")
    print("[SOC] Initialisation de la Baseline de comportement...")
    print("[SOC] En attente de logs pour le triage des alertes (MTTD/MTTR)...\n")
    
    # Expressions régulières (Behavior-based detection)
    mac_error_pattern = re.compile(r"MAC invalide|Tentative suspecte")
    buffer_overflow_pattern = re.compile(r"Segmentation fault|buffer overflow")
    sql_injection_pattern = re.compile(r"UNION SELECT|OR 1=1")
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            pass # Create the file
            
    with open(LOG_FILE, "r") as f:
        # Aller à la fin du fichier pour agir comme 'tail -f'
        f.seek(0, 2)
        
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                line = line.strip()
                # Print the raw log
                print(f"[{time.strftime('%H:%M:%S')}] {line}")
                
                # UEBA / SIEM Analysis
                if mac_error_pattern.search(line):
                    print(f"\n[ALERTE CRITIQUE] Attaque détectée (Malleability/POODLE) ! Violation d'intégrité EtM.")
                    print(f"[RÉPONSE] Blocage de l'IP réseau. Calcul du MTTR en cours...\n")
                elif buffer_overflow_pattern.search(line):
                    print(f"\n[ALERTE CRITIQUE] Tentative de Buffer Overflow détectée (Exploit mémoire) !")
                    print(f"[RÉPONSE] Isolation du processus. Forensics requis.\n")
                elif sql_injection_pattern.search(line):
                    print(f"\n[ALERTE CRITIQUE] Payload SQL Injection détecté dans les requêtes (Living-off-the-land) !")
                    print(f"[RÉPONSE] WAF activé sur les endpoints sensibles.\n")
        except KeyboardInterrupt:
            print("\n[SOC] Arrêt de la surveillance.")

if __name__ == "__main__":
    start_soc()
