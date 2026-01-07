import json
import os
import generateurchat as generateur

def main():
    fichier_intent = "Intent_file.json"

    if not os.path.exists(fichier_intent):
        print(f"Erreur : Le fichier {fichier_intent} est introuvable.")
        return

    with open(fichier_intent, "r") as f:
        data = json.load(f)

    output_dir = data.get("project_settings", {}).get("output_folder", "output")
    os.makedirs(output_dir, exist_ok=True)

    print("--- Début de la génération ---")

    for as_data in data.get("autonomous_systems", []):
        for router in as_data.get("routers", []):
            nom_routeur = router["name"]
            cfg = generateur.assembler_configuration(nom_routeur, data)

            path = os.path.join(output_dir, f"{nom_routeur}.cfg")
            with open(path, "w") as f_out:
                f_out.write(cfg)

            print(f"✅ Configuration générée pour : {nom_routeur}")

    print("--- Terminé avec succès ---")
    print(f"Les fichiers sont disponibles dans le dossier : {output_dir}/")

if __name__ == "__main__":
    main()
