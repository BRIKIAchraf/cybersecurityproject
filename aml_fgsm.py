import numpy as np

def fgsm_attack(x, y, weights, bias, epsilon=0.1):
    """
    Simule une attaque FGSM (Fast Gradient Sign Method) sur un classifieur linéaire.
    """
    # Prediction: w*x + b
    pred = np.dot(weights, x) + bias
    
    # Hinge Loss: max(0, 1 - y * pred)
    # Gradient of the loss with respect to x: -y * weights (if y * pred < 1)
    if y * pred < 1:
        gradient = -y * weights
    else:
        gradient = np.zeros_like(x)
        
    # Attack: add noise in the direction of the gradient
    x_adv = x + epsilon * np.sign(gradient)
    return x_adv

if __name__ == "__main__":
    print("==========================================================")
    print("--- Module 6 : Adversarial Machine Learning (Attaque FGSM) ---")
    print("==========================================================\n")
    
    # Caractéristiques d'un Malware (ex: appels API suspects, entropie)
    x_initial = np.array([0.8, 0.6, 0.2, 0.9])
    y_true = 1 # 1 = Malware, -1 = Sain
    
    # Poids du modèle de Machine Learning pré-entraîné
    weights = np.array([0.5, 0.4, -0.2, 0.7])
    bias = -0.5
    
    score_initial = np.dot(weights, x_initial) + bias
    label_initial = "MALWARE" if score_initial > 0 else "SAIN"
    print(f"[*] Vecteur initial : {x_initial}")
    print(f"[*] Score du modèle : {score_initial:.2f} -> Classification : {label_initial}\n")
    
    print("[!] Injection de bruit antagoniste (FGSM) par l'attaquant...")
    x_adverse = fgsm_attack(x_initial, y_true, weights, bias, epsilon=0.6)
    
    score_adverse = np.dot(weights, x_adverse) + bias
    label_adverse = "MALWARE" if score_adverse > 0 else "SAIN"
    print(f"[*] Vecteur altéré  : {np.round(x_adverse, 2)}")
    print(f"[*] Nouveau Score   : {score_adverse:.2f} -> Classification : {label_adverse}")
    
    if label_adverse == "SAIN":
        print("\n=> SUCCÈS DE L'ATTAQUE : L'IA de détection (SOC) a été trompée et considère le malware comme légitime !")
