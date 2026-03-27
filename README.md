# TP1 : Analyse de trames réseaux

## Objectif
Identifier les trames Wi-Fi d’identification et de localisation de drones et extraire les informations pertinentes avec un programme en Rust.

## Fonctionnement
Le programme prend en entrée soit un fichier PCAP, soit une capture en temps réel. Dans les deux cas :  
- Affiche les paquets capturés (jusqu'à `--packet-count`) dans le terminal.  
- Analyse les trames Beacon et DroneID et extrait les informations nécessaires.  
- Sauvegarde les résultats dans un fichier selon le format demandé.
  
**Important** : 
- La partie 6 n'a réussi à fonctionner que sur un appareil sur linux, et non sur la VM car on pas réussi à détecter la carte Wifi (malgré les changements de paramètre réseau sur VirutalBox).

- Elle ne fonctionne également pas sur Windows car on n'arrive pas à mettre la carte en mode moniteur.

### Analyse d’un fichier PCAP
```bash
cargo run -- --pcap nom_fichier.pcap --packet-count 50 --output-file results.json --output-format json
