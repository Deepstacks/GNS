# main.py
import json
import os
import generateurchat as generateur # On importe notre module personnel

def main():
    # 1. Chargement du fichier d'intention
    fichier_intent = 'Intent_file.json'
    
    if not os.path.exists(fichier_intent):
        print(f"Erreur : Le fichier {fichier_intent} est introuvable.")
        return

    with open(fichier_intent, 'r') as f:
        data = json.load(f)

    # 2. Préparation du dossier de sortie
    output_dir = data.get('project_settings', {}).get('output_folder', 'output')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Dossier '{output_dir}' créé.")

    print("--- Début de la génération ---")

    # 3. Boucle sur chaque routeur
    for as_data in data.get('autonomous_systems', []):
        for router in as_data.get('routers', []):
            nom_routeur = router['name']

            # Appel de la fonction d'assemblage en passant l'intent complet
            config_complete = generateur.assembler_configuration(nom_routeur, data)

            # Écriture du fichier .cfg
            chemin_fichier = os.path.join(output_dir, f"{nom_routeur}.cfg")

            with open(chemin_fichier, 'w') as f_out:
                f_out.write(config_complete)

            print(f"✅ Configuration générée pour : {nom_routeur}")

    print("--- Terminé avec succès ---")
    print(f"Les fichiers sont disponibles dans le dossier : {output_dir}/")

if __name__ == "__main__":
    main()