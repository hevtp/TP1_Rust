//! # TP1 : Analyse de trames réseaux par Agathe Julien et Hevisinda Top
//!
//! Objectif : Identifier les trames Wifi d'identification et de localisation de drones et extraire les informations pertinentes de ces trames à l'aide d'un programme en Rust.
//!
//! Le programme prend en entrée le fichier PCAP puis :
//! - Affiche les paquets capturés ( jusqu'à '--packet-count') dans le terminal.
//! - Analyse les trames Beacon et de Drone et extrait les informations nécessaires.
//! - sauvegarde les résultats dans un fichier selon le format demandé.
//!
//! Si `--pcap` est absent ou si le fichier n'existe pas, une erreur est retournée.
//!
//! La réponse à la partie 2 du TP se trouve dans le dossier analyse_wireshark.


use clap::Parser;
use pcap::Capture;
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
    let pcap_filename = match args.pcap {
        Some(filename) => filename,
        None => return Err("Merci de fournir --pcap <nom_fichier.pcap|pcapng>".into()),
    };

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
    
    Ok(())
}
