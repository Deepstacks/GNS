Pour mettre en place les résultats de notre projet de la meilleure des manières, veuillez suivre les consignes suivantes : 

1) Ouvrez le fichier GNS.gns3 dans GNS3 SANS lancer les nodes

2) dans un terminal accédez au fichier GNS fourni et lancez le fichier main.py avec:
   python3 main.py 
   
#A ce niveau vous maintenant créé les configs des différents routeurs dans output

3) maintenant, déployez les config dans GNS3 en utilisant la commande : 
   python3 deploy_to_gns3.py \
  --project " ~ /GNS/partie_gns" \
  --generated "output" \
  --backup

#attention a bien remplacer " ~ " par votre arborescence à vous. exemple moi ca donnait ca :
#python3 deploy_to_gns3.py \
  --project "$HOME/Documents/Github/GNS/partie_gns" \
  --generated "output" \
  --backup

4) Vous pouvez maintenant start all nodes dans GNS3 et étudier nos résultats