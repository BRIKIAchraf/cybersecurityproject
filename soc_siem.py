"""
soc_siem.py -- Centre Operationnel de Securite (Blue Team)
==========================================================
SIEM ameliore avec detection FGSM/AML en plus des regles existantes.
Lance ce script dans un terminal séparé (PC de votre amie / Bob).
"""

import time
import re
import os
import sys

# --- Force UTF-8 stdout on Windows ----------------------------------------
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

LOG_FILE = "sentinelle_soc.log"

# ─── Tentative d'import numpy pour la détection AML (optionnel) ─────────────
try:
    import numpy as np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False


def _run_aml_detection_test():
    """
    Teste la robustesse du modèle ML interne contre une attaque FGSM.
    Si l'attaque réussit → alerte critique (le SOC doit l'entraîner à nouveau).
    """
    if not _NUMPY_OK:
        return

    # Modèle de détection de trafic malveillant (simplifié)
    weights = np.array([0.5, 0.4, -0.2, 0.7])
    bias    = -0.5

    # Vecteur de trafic suspect (devrait être classé MALVEILLANT)
    x     = np.array([0.8, 0.6, 0.2, 0.9])
    y_true = 1  # 1 = Malveillant

    score_initial = np.dot(weights, x) + bias
    label_initial = "MALVEILLANT" if score_initial > 0 else "BÉNIN"

    # Attaque FGSM (Fast Gradient Sign Method)
    epsilon   = 0.6
    if y_true * score_initial < 1:
        gradient = -y_true * weights
    else:
        gradient = np.zeros_like(x)
    x_adv = x + epsilon * np.sign(gradient)

    score_adv  = np.dot(weights, x_adv) + bias
    label_adv  = "MALVEILLANT" if score_adv > 0 else "BÉNIN"

    if label_adv == "BÉNIN" and label_initial == "MALVEILLANT":
        print(f"\n[ALERTE IA] ⚠️  Attaque FGSM adversariale réussie sur le modèle ML !")
        print(f"[ALERTE IA]    Score initial  : {score_initial:.3f} → {label_initial}")
        print(f"[ALERTE IA]    Score perturbé : {score_adv:.3f} → {label_adv}")
        print(f"[ALERTE IA]    Vecteur altéré : {np.round(x_adv, 2)}")
        print(f"[RÉPONSE IA]   Re-entraînement du modèle avec exemples adversariaux...\n")
    else:
        print(f"[SOC] ✅  Test AML : Modèle robuste (score = {score_adv:.3f})\n")


def start_soc():
    print("═" * 62)
    print("  🛡️  MODULE 7 : SIEM SOC — Centre Opérationnel de Sécurité")
    print("═" * 62)
    print("[SOC] Initialisation de la Baseline de comportement...")
    print("[SOC] Règles de détection chargées :")
    print("      • MAC invalide / Violation d'intégrité (Malleability/POODLE)")
    print("      • Buffer Overflow / Segmentation Fault")
    print("      • SQL Injection (UNION SELECT, OR 1=1)")
    print("      • Bypass ML Adversarial (FGSM) ← NOUVEAU")
    print("[SOC] En attente de logs pour le triage (MTTD/MTTR)...\n")

    # ── Règles de détection (Behavior-Based Detection) ───────────────────────
    patterns = {
        "MAC invalide|Tentative suspecte": (
            "CRITIQUE",
            "Attaque Malleability/POODLE ! Violation d'intégrité EtM.",
            "Blocage IP réseau. Calcul MTTR en cours."
        ),
        r"Segmentation fault|buffer overflow": (
            "CRITIQUE",
            "Tentative de Buffer Overflow (exploit mémoire) !",
            "Isolation du processus. Forensics requis."
        ),
        r"UNION SELECT|OR 1=1": (
            "CRITIQUE",
            "Payload SQL Injection détecté (Living-off-the-land) !",
            "Activation du WAF sur les endpoints sensibles."
        ),
        r"FGSM|adversarial|AML|bypass.model|modèle trompé": (
            "CRITIQUE",
            "Contournement du modèle ML par attaque adversariale (FGSM/AML) !",
            "Re-entraînement du modèle. Ajout d'exemples adversariaux au dataset."
        ),
        r"MITM|Man-in-the-Middle|signature.invalide": (
            "CRITIQUE",
            "Attaque Man-in-the-Middle détectée ! Certificat forgé.",
            "Révocation de la session. Alerte PKI."
        ),
        r"Replay|paquet fantôme|rejeu": (
            "ÉLEVÉE",
            "Attaque par Rejeu détectée ! Nonce réutilisé.",
            "Invalidation du nonce de session. Rotation des clés."
        ),
        r"OT_REQUEST|COMMIT_FAIL|ZKP.*ECHOUE": (
            "MODÉRÉE",
            "Comportement anormal dans le protocole de session.",
            "Audit de session. Monitoring renforcé."
        ),
    }
    compiled_patterns = [
        (re.compile(k), v) for k, v in patterns.items()
    ]

    # ── Test AML initial (robustesse du modèle ML) ───────────────────────────
    print("[SOC] Test de robustesse AML du modèle de détection...")
    _run_aml_detection_test()

    # ── Surveillance continue du fichier de logs ─────────────────────────────
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            pass

    aml_test_counter = 0

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # Aller à la fin (mode tail -f)

        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    aml_test_counter += 1
                    # Test AML automatique toutes les 60 secondes
                    if aml_test_counter >= 120:
                        aml_test_counter = 0
                        print("\n[SOC] ⏱️  Test AML périodique du modèle ML...")
                        _run_aml_detection_test()
                    continue

                line = line.strip()
                ts   = time.strftime('%H:%M:%S')
                print(f"[{ts}] {line}")

                for pattern, (severity, threat, response) in compiled_patterns:
                    if pattern.search(line):
                        print(f"\n{'─'*60}")
                        print(f"  [ALERTE {severity}] 🚨  {threat}")
                        print(f"  [RÉPONSE]          {response}")
                        print(f"  [MTTR]             Détection à {ts} — Réponse immédiate.")
                        print(f"{'─'*60}\n")
                        break

        except KeyboardInterrupt:
            print("\n[SOC] Surveillance arrêtée.")


if __name__ == "__main__":
    start_soc()
