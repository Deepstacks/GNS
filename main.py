# main.py
import json
import os
import generateur # On importe notre module personnel

def main():
    # 1. Chargement du fichier d'intention
    fichier_intent = 'intent.json'
    
    if not os.path.exists(fichier_intent):
        print(f"Erreur : Le fichier {fichier_intent} est introuvable.")
        return

    with open(fichier_intent, 'r') as f:
        data = json.load(f)

    # 2. Préparation du dossier de sortie
    output_dir = data['project_settings']['output_folder']
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Dossier '{output_dir}' créé.")

    print("--- Début de la génération ---")

    # 3. Boucle sur chaque routeur
    for router in data['routers']:
        nom_routeur = router['hostname']
        
        # Appel de la fonction "magique" située dans l'autre fichier
        config_complete = generateur.assembler_configuration(router)
        
        # Écriture du fichier .cfg
        chemin_fichier = os.path.join(output_dir, f"{nom_routeur}.cfg")
        
        with open(chemin_fichier, 'w') as f_out:
            f_out.write(config_complete)
            
        print(f"✅ Configuration générée pour : {nom_routeur}")

    print("--- Terminé avec succès ---")
    print(f"Les fichiers sont disponibles dans le dossier : {output_dir}/")

if __name__ == "__main__":
    main()