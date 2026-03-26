//! # TP1 : Analyse de trames réseaux par Agathe Julien et Hevisinda Top
//!
//! Objectif : Identifier les trames Wifi d'identification et de localisation de drones et extraire les informations pertinentes de ces trames à l'aide d'un programme en Rust.
//!
//! Le programme prend en entrée soit un fichier PCAP soit lance une capture en temps réel. Dans les deux cas, il effectue les opérations suivantes :
//! - Affiche les paquets capturés ( jusqu'à '--packet-count') dans le terminal.
//! - Analyse les trames Beacon et de Drone et extrait les informations nécessaires.
//! - sauvegarde les résultats dans un fichier selon le format demandé.
//!
//! Si `--pcap` est absent ou si le fichier n'existe pas, une erreur est retournée. De même, pour la capture en temps réel.
//! Si `--interface` est fourni sur Windows, une erreur est retournée car le mode monitor n'est pas supporté.
//!
//! On souligne également que la partie 6 n'a réussi à fonctionner que sur un appareil sur linux, et non sur la VM car on pas réussi à détecter la carte Wifi (malgré les changements de paramètre réseau sur VirutalBox).
//! Elle ne fonctionne également pas sur Windows car on n'arrive pas à mettre la carte en mode moniteur.
//!
//! La réponse à la partie 2 du TP se trouve dans le dossier analyse_wireshark.


use clap::Parser;
use pcap::{Capture, Device};
use std::path::PathBuf;

//Import des modules de lib
use tp1_rust::args::Args;
use tp1_rust::pcap_analysis::{extract_beacon_info, extract_droneid_info};
use tp1_rust::models::{ Beacon, AnalysisResult, Drone};
use tp1_rust::output::{save_output, log_line};
const PCAP_BASE_DIRS: [&str; 2] = ["captures", "../captures"]; //chemin fichier de capture à étudier

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal_lines: Vec<String> = Vec::new(); //pour conserver les lignes de sortie
    let mut beacons: Vec<Beacon> = Vec::new(); //Pour stocker les lignes Beacon
    let mut drones: Vec<Drone> = Vec::new(); //Pour stocker les informations sur les drones

    // Parse les arguments de ligne de commande et vérifie la présence du fichier PCAP.
    let args = Args::parse();

    // Si aucun argument n’est fourni
    if args.pcap.is_none() && args.interface.is_none() {
        println!("Aucun fichier PCAP ni interface fournie");
        println!("Utilisez --pcap <nom_fichier> ou --interface <nom_interface>.");
        return Ok(());
    }

    //Fichier PCAP
    if let Some(pcap_filename) = args.pcap {

        // On cherche le fichier PCAP dans les répertoires spécifiés dans `PCAP_BASE_DIRS`. Si le fichier n'est pas trouvé, une erreur détaillée est retournée.
        let pcap_path = PCAP_BASE_DIRS
            .iter()
            .map(|base| PathBuf::from(base).join(&pcap_filename))
            .find(|candidate| candidate.exists())
            .unwrap_or_else(|| PathBuf::from(PCAP_BASE_DIRS[0]).join(&pcap_filename));

        // Vérifie que le fichier PCAP existe avant de tenter de l'ouvrir. Si le fichier est introuvable, une erreur détaillée est retournée avec les chemins testés.
        if !pcap_path.exists() {
            let cwd = std::env::current_dir()?;
            return Err(format!(
                "Fichier introuvable: {}\nRépertoire courant: {}\nDossiers PCAP testés: {:?}",
                pcap_path.display(),
                cwd.display(),
                PCAP_BASE_DIRS
            )
                .into());
        }

        // Ouvre le fichier PCAP avec la bibliothèque pcap. Si l'ouverture échoue, une erreur détaillée est retournée.
        let mut cap = Capture::from_file(&pcap_path)?;

        log_line(&mut terminal_lines, " ");
        log_line(&mut terminal_lines, "=== Analyse du fichier PCAP ===");
        log_line(&mut terminal_lines, "");

        // Lit les paquets un à un avec `next_packet` et affiche au plus `--packet-count` paquets. Si la lecture d'un paquet échoue, la boucle se termine.
        for packet_index in 1..=args.packet_count {
            match cap.next_packet() {
                //affiche les informations de chaque paquet dans le terminal et les stocke dans `terminal_lines`
                Ok(packet) => log_line(&mut terminal_lines, &format!("Paquet #{packet_index} : {:?}", packet)),
                Err(_) => break,
            }
        }

        // Réouvre le fichier PCAP pour analyser les trames beacons
        let mut cap = Capture::from_file(&pcap_path)?;



        log_line(&mut terminal_lines, "");
        log_line(&mut terminal_lines, "=== Analyse des trames Beacon ===");
        log_line(&mut terminal_lines, "");
        let mut beacon_count = 0usize;
        let packet_count: usize = args.packet_count as usize;

        while let Ok(packet) = cap.next_packet() {
            if beacon_count >= packet_count {
                break;
            }
            if let Some((ssid, mac_addr)) = extract_beacon_info(packet.data) {
                beacon_count += 1;
                log_line(
                    &mut terminal_lines,
                    &format!("Beacon #{}: SSID='{}' MAC={}", beacon_count, ssid, mac_addr),
                );
                //Stock les valeurs dans la structure "Beacons"
                beacons.push(Beacon{
                    ssid,
                    mac: mac_addr,
                })
            }
        }

        if beacon_count == 0 {
            log_line(
                &mut terminal_lines,
                "Aucune trame beacon trouvée dans le fichier PCAP.",
            );
        } else {
            log_line(
                &mut terminal_lines,
                &format!(" Total: {} trames beacon détectées.", beacon_count),
            );
        }

        // Réouvre le fichier pour analyser les trames DroneID (Vendor Specific 0xdd)
        let mut cap = Capture::from_file(&pcap_path)?;
        log_line(&mut terminal_lines, "");
        log_line(&mut terminal_lines, "=== Analyse des trames DroneID ===");
        log_line(&mut terminal_lines, "");

        let mut droneid_count = 0usize;
        while let Ok(packet) = cap.next_packet() {
            if droneid_count >= packet_count {
                break;
            }
            if let Some(details) = extract_droneid_info(packet.data) {
                droneid_count += 1;
                log_line(
                    &mut terminal_lines,
                    &format!("DroneID #{}: {}", droneid_count, details),
                );

                //Stock les valeurs dans la structure "Drone"
                drones.push(Drone{
                    details,
                })

            }
        }

        if droneid_count == 0 {
            log_line(
                &mut terminal_lines,
                "Aucune trame DroneID (CID 6A:5C:35) détectée.",
            );
        } else {
            log_line(
                &mut terminal_lines,
                &format!(" Total: {} trames DroneID détectées.", droneid_count),
            );
        }


        let result = AnalysisResult {
            pcap_file: pcap_filename.clone(),
            beacons,
            drone_ids: drones,
        };

        save_output(&args.output_format, &args.output_file, &result)?;

        println!(
            "Résultats sauvegardés dans {} au format {}",
            args.output_file, args.output_format
        );

    }
    //Capture en temps réel
    else if let Some(interface_name) = args.interface {

        //Vérifie si on est sur windows
        if cfg!(target_os = "windows") {
            return Err("La capture en mode monitor n'est malheureusement pas supportée sur Windows...désolée.".into());
        }

        // Récupère la liste des interfaces
        let devices = Device::list()
            .map_err(|e| format!("Impossible de récupérer la liste des interfaces : {}", e))?;

        // Vérifie que l'interface existe sinon donne la liste des interfaces disponibles.
        if devices.iter().find(|d| d.name == interface_name).is_none() {
            println!("Interface '{}' non trouvée !", interface_name);
            println!("Interfaces disponibles :");
            for (i, dev) in devices.iter().enumerate() {
                println!("  [{}] {}", i, dev.name);
            }
            return Err("Interface non trouvée. Relancez avec --interface <nom_de_interface>".into());
        }

        //active la capture
        let mut cap = Capture::from_device(interface_name.as_str())?
            .immediate_mode(true)
            .open()?;

        log_line(&mut terminal_lines, "\n=== Capture en temps réel ===\n");

        //filtre pour ne capturer que les trames Wifi 802.11
        cap.filter("wlan type mgt", true)?;

        let mut packet_index = 0usize;

        //Lit les paquets capturés et passe au suivant jusqu'à packet_count en utilisant le même principe que pour le fichier PCAP
        while let Ok(packet) = cap.next_packet() {
            packet_index += 1;
            if packet_index >= args.packet_count as usize {
                break;
            }

            // Extraction des beacons
            if let Some((ssid, mac_addr)) = extract_beacon_info(packet.data) {
                log_line(&mut terminal_lines, &format!("Beacon #{}: SSID='{}' MAC={}", packet_index, ssid, mac_addr));
                beacons.push(Beacon { ssid, mac: mac_addr });
            }


            // Extraction des DroneID
            if let Some(details) = extract_droneid_info(packet.data) {
                log_line(&mut terminal_lines, &format!("DroneID #{}: {}", packet_index, details));
                drones.push(Drone { details });
            }
        }

        // Indique si aucune trame n'a été détectée
        if beacons.is_empty() {
            log_line(&mut terminal_lines, "Aucune trame Beacon détectée.");
        }

        if drones.is_empty() {
            log_line(&mut terminal_lines, "Aucune trame DroneID détectée.");
        }

        // Sauvegarde des résultats
        let result = AnalysisResult {
            pcap_file: format!("live_capture_{}", interface_name),
            beacons,
            drone_ids: drones,
        };


        save_output(&args.output_format, &args.output_file, &result)?;
        println!("Résultats sauvegardés dans {} au format {}", args.output_file, args.output_format);

    }

    Ok(())
}