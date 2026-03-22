
///TP1 : Analyse de trames réseaux par Agathe Julien et Hevisinda Top
///Objectif : Identifier les trames Wifi d'identification et de localisation de drones et extraire les informations pertinentes de ces trames à l'aide d'un programme en Rust.
/// Partie 1: Arguments de ligne de commande et documentation
/// Cette partie permet de définir et gérer les différents
/// arguments passés au programme en ligne de commande.
///La gestion des arguments est réalisée avec la bibliothèque clap
///On choisit d'utiliser le mode derive car plus lisible et intuitif.

use clap::{Parser};
use serde::Serialize;


/// Arguments de ligne de commande du programme.
/// 
/// Utiliser `--pcap` pour indiquer le fichier à lire et `--packet-count`
/// pour limiter le nombre de paquets affichés. 
/// `--interface`permet de spécifier une interface réseau pour la capture en temps réel, `--cards` affiche la liste des interfaces réseau disponibles, `--filter` permet d'appliquer un fitre de capture, `--output-format` spécifie le format de sortie des résultats (par défaut JSON), et `--output-file` indique le nom du fichier de sortie (par défaut results.json).

#[derive(Parser, Debug)]

struct Args{

    ///Interface réseau pour capture en temps réel
    /// On précise conflicts_with, car incompatible avec --pcap
    #[arg(long, conflicts_with = "pcap")]
    interface : Option<String>,

    ///Fichier PCAP à analyser
    /// Incompatible avec --interface
    #[clap(long, conflicts_with = "interface")]
    pcap : Option<String>,

    ///Affiche la liste des interfaces réseau disponibles puis quitte le programme
    #[arg(long)]
    cards : bool,

    /// Filtre de capture à appliquer
    #[clap(long)]
    filter : Option<String>,

    /// Filtre de capture à appliquer, par défault 10
    #[clap(long, default_value = "10")]
    packet_count : u32,

    /// Format de sortie des résultats, par défault JSON

    #[clap(long, default_value = "json")]
    output_format : String,
    /// Nom du fichier de sortie, par défault result.json
    #[clap(long, default_value = "results.json")]
    output_file : String,

}

///Partie 2 : Analyse du fichier PCAP avec Wireshark
/// Dans cette seconde partie, nous analysons le fichier de capture PCAP fourni sur Moodle à l'aide de Wireshark.
/// La capture a été réalisée en mode "monitor" avec une carte Wi-Fi, ce qui permet de capturer toutes les trames présentes dans l’air, y compris les trames de gestion (management frames) et de contrôle.
/// On observe plusieurs types d'appareils présents sur le réseau (Apple, Huawei, Xiaomi, etc.), qui communiquent via le protocole **Wi-Fi 802.11**.
///
/// Parmi les trames capturées, on distingue notamment :
///
/// - **Trames de données QoS (Quality of Service)** : Elles contiennent les **données utilisateurs**.
/// Exemple : une trame `QoS Data` de l’adresse `Apple_09:fe:be` vers `HuaweiTechno_30:6b:20`.

/// - **Trames Acknowledgement (ACK)** : permet de confirmer la bonne réception de la trame précedente. Elles sont uniquement en unicast.
///
/// - **Trames AWDL (Apple Wireless Direct Link)** : envoyées en broadcast par des appareils Apple pour permettre la communication directe entre eux, par exemple pour le AirDrop.
///   Exemple : l’adresse MAC `66:19:11:f0:12:4d` envoie une trame AWDL.
///
/// - **Trames Beacon** : envoyées en broadcast, c'est à dire à toutes les stations à portée. Ces trames annoncent la présence d’un réseau et contiennent des informations comme le **SSID** et l’**intervalle de beacon**.
///    Exemple : l’adresse MAC `86:2a:fd:a4:df:68` envoie une trame Beacon pour le réseau `"DIRECT-68-HP"`.
///
/// - **Intervalle de Beacon** : spécifie la durée entre les émissions successives de Beacon.
///  Il permet de savoir à quelle fréquence un client peut s’attendre à recevoir ces trames de balise.
///
/// - **Application dans le cas des drones**  : Dans le ca sdes drones, ce type de trame est utilisé par les drones pour signaler leur présence et leur position aux autorités. En analysant ces trames, on peut obtenir des informations sur les drones présents dans la zone de capture, telles que leur ID, leur position GPS, leur altitude, etc.
/// Ces trames sont définies par l'arrêté publié au journal officiel et sont utilisées par les drones pour se conformer à la réglementation en vigueur en matière de sécurité aérienne.
///
/// On peut repérer ces trames de droneID dans le fichier PCAP. En effet, d'après la documentation officielle :
/// - Les trames utilisent le protocole Wi-Fi conforme à la norme IEEE 802.11 (version 2016).
/// - Ce sont des **trames de gestion** (type 0) de sous-type 8, correspondant aux **Beacon frames**.
/// - Elles sont transmises sur la bande 2,4 GHz (canaux Wi-Fi France, largeur 20 MHz standard, 5 ou 10 MHz possibles).
/// - Le message spécifique au drone se trouve dans le **payload vendor-specific** de la trame, avec le numéro CID `6A-5C-35`.
/// - La charge utile contient un numéro de version (1 octet, valeur 1) et un identifiant unique du drone (DroneID), codé sur 30 octets selon la norme ANSI/CTA/2063.
///
/// Par exemple,sur wireshark, on filtre les trame Broadcast, et on choisit une trame de source Expressif_dd:b0:bd, et on va dans la catégorie Tag: Vendor Specific: Secrétariat général de la défense et de la sécurité natio
///
///On identifie le DroneID :Tag: ID FR: 000 ENS EATHESEUS202300000000001
///Ses coordonnées : Latitude: -5863,96928, Tag: Longitude: 17394,57280


/// Partie 3 : Analyse du fichier PCAP avec Rust.
/// Il s'agit d'écrire un programme en Rust pour analyser ce fichier PCAP et extraire les informations pertinentes de ces trames "beacon" de localisation de drones.

use pcap::Capture;
use std::fs; 
use std::path::PathBuf;

const PCAP_BASE_DIRS: [&str; 2] = ["captures", "../captures"];
const DRONE_CID: [u8; 3] = [0x6A, 0x5C, 0x35]; //CID spécifique pour les trames DroneID selon la documentation officielle


/// Le programme ouvre un fichier PCAP fourni via `--pcap`, lit les paquets un à un avec `next_packet` et affiche au plus `--packet-count` paquets. 
/// Si `--pcap` est absent ou si le fichier n'existe pas, une erreur est retournée. 



fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal_lines: Vec<String> = Vec::new(); //pour stocker les lignes de sortie et les enregistrer dans un fichier JSON à la fin 

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
   
    
    while let Ok(packet) = cap.next_packet() {
        if let Some((ssid, mac_addr)) = extract_beacon_info(packet.data) {
            beacon_count += 1;
            log_line(
                &mut terminal_lines,
                &format!("Beacon #{}: SSID='{}' MAC={}", beacon_count, ssid, mac_addr),
            );
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
        if let Some(details) = extract_droneid_info(packet.data) {
            droneid_count += 1;
            log_line(
                &mut terminal_lines,
                &format!("DroneID #{}: {}", droneid_count, details),
            );
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

    //enregistre la sortie terminal dans un fichier JSON si le format de sortie est spécifié comme "json". Si un format non supporté est spécifié, un message d'erreur est affiché dans le terminal
    if args.output_format.eq_ignore_ascii_case("json") {
        save_terminal_output_json(&args.output_file, &pcap_filename, &terminal_lines)?;
        println!("Sortie terminal enregistrée dans {}", args.output_file);
    } else {
        println!(
            "Format '{}' non supporté pour l'export terminal. Utilise --output-format json.",
            args.output_format 
        );
    }
    
    Ok(())
}

#[derive(Serialize)] //sérialisation en JSON de la structure TerminalOutput pour pouvoir l'enregistrer dans un fichier JSON
struct TerminalOutput {
    pcap_file: String, 
    lines: Vec<String>, 
}

/// Affiche un message dans le terminal et l'ajoute à la liste des lignes pour l'enregistrer dans un fichier JSON à la fin
fn log_line(lines: &mut Vec<String>, message: &str) {
    println!("{}", message);
    lines.push(message.to_string());
}

/// Enregistre la sortie dans un fichier JSON avec le nom du fichier PCAP
fn save_terminal_output_json(
    output_file: &str,
    pcap_file: &str, 
    lines: &[String],
) -> Result<(), Box<dyn std::error::Error>> { 
    let payload = TerminalOutput { 
        pcap_file: pcap_file.to_string(), 
        lines: lines.to_vec(), 
    };

    //on sérialise la structure TerminalOutput en JSON avec une mise en forme lisible avec to_string_pretty et on l'écrit dans le fichier de sortie spécifié
    let json = serde_json::to_string_pretty(&payload)?; 
    fs::write(output_file, json)?;
    Ok(())
}

/// Extrait la taille du header Radiotap (octets 2-3, little-endian)
fn get_radiotap_length(data: &[u8]) -> usize {
    // Si le paquet est trop court pour contenir un header Radiotap complet, on retourne 0 pour éviter les erreurs d'indexation
    if data.len() < 4 { 
        return 0;
    }
    // les octets 2-3 du header Radiotap contiennet la longueur totale du header Radiotap en little-endian 
    // u16::from_le_bytes convertit ces deux octets en un entier de 16 bits qui représente la longueur du header. On le convertit ensuite en usize pour l'utiliser comme index
    u16::from_le_bytes([data[2], data[3]]) as usize
}

/// Extrait le type et sous-type (premiers 2 octets de l'en-tête 802.11)

/// On a vu sur la capture Wireshark que les trames de type beacon ont un frame control de 0x8000, ce qui correspond à un type de trame 0 (management) et un sous-type de 8 (beacon)
/// Le champ est lu en little-endian (octet faible puis octet fort), donc les bits utiles correspondent à 0x0080 (type 0, subtype 8) après conversion en entier
/// Avec 0x0080, les bits de type (bits 2-3) sont 00 (type management) et les bits de sous-type (bits 4-7) sont 1000 (sous-type beacon) 

/// On voit également sur Wireshark que les bits 0 et 1 sont les bits de version donc on les ignore en décalant de 2 positions vers la droite (>>2) pour extraire le type, et de 4 positions vers la droite (>>4) pour extraire le sous-type
/// On applique ensuite des masques binaires pour ne conserver que les bits pertinents: &0x3 pour le type (2 bits) et &0xf pour le sous-type (4 bits)

fn get_frame_type_subtype(fc: u16) -> (u8, u8) {
    // le frame control est un champ de 16 bits dans l'entête 802.11 qui contient des informations sur le type de trame, le sous-type, etc.
    let frame_type = ((fc >> 2) & 0x3) as u8;
    let frame_subtype = ((fc >> 4) & 0xf) as u8;
    (frame_type, frame_subtype)
}

/// Extrait l'adresse MAC (BSSID) à partir de l'en-tête 802.11 MAC
/// D'après le format de cet en-tête de taille 24 octets, l'adresse MAC BSSID se trouve à l'offset 16 (octet 16-21)
fn get_mac_address(data: &[u8], offset: usize) -> String {
    // si le paquet est trop court pour contenir une adresse MAC à l'offset, on retourne une adresse MAC invalide pour éviter les erreurs 
    // une adresse MAC est constituée de 6 octets
    if data.len() < offset + 6 {
        return "??:??:??:??:??:??".to_string();
    }
    // formate les 6 octets de l'adresse MAC en chaine de caractères en hexa, séparés par des deux points pour correspondre au format standard d'une adresse 
    // {:02x} formate chaque octet en deux chiffres hexa avec un zéro de remplissage si besoin
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        data[offset], data[offset + 1], data[offset + 2],
        data[offset + 3], data[offset + 4], data[offset + 5]
    )
}

/// Extrait le SSID du TLV (Type=0x00)
fn extract_ssid(data: &[u8], offset: usize) -> Option<String> {
    // pos est l'offset de départ pour parcourir les TLV jusqu'à la fin du paquet. On lit le type et la longueur de chaque TLV pour trouver ceux de type 0x00 qui correspondent au SSID
    let mut pos = offset;
    
    // while pour parcourir les TLV tant qu'il reste au moins 2 octets pour lire le type et la longueur
    while pos + 1 < data.len() {
        let tag_type = data[pos]; //1 octet pour le type du TLV
        let tag_len = data[pos + 1] as usize; //1 octet pour la longueur du TLV, converti en usize pour l'utiliser comme index
        
        if tag_type == 0x00 { //type 0x00 correspond au SSID
            if pos + 2 + tag_len <= data.len() { 
                let ssid_bytes = &data[pos + 2..pos + 2 + tag_len];
                return Some(String::from_utf8_lossy(ssid_bytes).to_string()); //convertit les octets du SSID en chaine de caractères, from_utf8_lossy permet de gérer les octets invalides en les remplaçant 
            }
        }
        
        pos += 2 + tag_len; //on passe au TLV suivant
        
        if pos > data.len() { //si on dépasse la fin du paquet, on sort de la boucle
            break;
        }
    }
    
    None // si aucun TLV de type SSID n'est trouvé, on retourne None
}

/// Analyse un paquet et retourne (SSID, adresse MAC) s'il s'agit d'une trame beacon
fn extract_beacon_info(data: &[u8]) -> Option<(String, String)> {
    //on récupère la longueur du header Radiotap pour savoir où commence l'en-tête 802.11 
    let radiotap_len = get_radiotap_length(data);
    if radiotap_len >= data.len() { //vérifie que le paquet est assez long pour contenir un header Radiotap complet
        return None;
    }
    
    //en-tête 802.11 commence juste après le header Radiotap
    let fc_offset = radiotap_len;
    if fc_offset + 2 > data.len() { 
        return None;
    }
    
    //on récupère le frame control pour vérifier le type et le sous-type de la trame
    let frame_control = u16::from_le_bytes([data[fc_offset], data[fc_offset + 1]]); //from_le_bytes lit les 2 octets du frame control en little-endian pour obtenir un entier de 16 bits qui contient les infos sur le type et le sous-type
    let (frame_type, frame_subtype) = get_frame_type_subtype(frame_control);
    
    //on vérifie que c'est une trame de type 0 et de sous-type 8 pour une trame beacon
    if frame_type != 0 || frame_subtype != 8 {
        return None;
    }
    
    //on récupère l'adresse MAC BSSID
    let mac_offset = fc_offset + 16; //l'adresse se trouve à l'offset 16 de l'en-tête 802.11, donc on ajoute 16 à l'offset du frame control 
    let mac_addr = get_mac_address(data, mac_offset);

    //pour les trames beacon, les données sous format TLV commencent après les 24 octets de l'en-tête MAC et les 12 octets d'en-tête des paramètres fixes du beacon, soit au total 36 octets après le frame control
    let tlv_offset = fc_offset + 36;
    
    //on extrait le SSID du TLV à partir de tlv_offset
    let ssid = extract_ssid(data, tlv_offset).unwrap_or_else(|| "<SSID vide>".to_string());
    
    Some((ssid, mac_addr)) 
}

/// Extrait les éléments vendor-specific (type 0xdd) et retourne une liste de leurs valeurs

fn extract_vendor_specific_elements(data: &[u8], tlv_offset: usize) -> Vec<Vec<u8>> {
    let mut vendors = Vec::new(); 
    let mut pos = tlv_offset; 

    while pos + 1 < data.len() { 
        let tag_type = data[pos];
        let tag_len = data[pos + 1] as usize;

        if pos + 2 + tag_len > data.len() {
            break;
        }

        if tag_type == 0xdd { //type 0xdd correspond aux éléments vendor-specific
            vendors.push(data[pos + 2..pos + 2 + tag_len].to_vec()); 
        }

        pos += 2 + tag_len; 

        if pos > data.len() { 
            break;
        }
    }
    vendors
}

//Structure pour stocker les champs extraits d'une trame DroneID, Option gère la présence ou l'absence de chaque champ dans la trame
#[derive(Default)]
struct DroneIdFields {
    protocol_version: Option<u8>, 
    id_fr: Option<String>,
    id_ansi: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    altitude_m: Option<i16>,
    height_m: Option<i16>,
}

///Convertit un tableau d'octets en une chaine de caractères UTF-8
fn bytes_to_utf8(value: &[u8]) -> String {
    let s = String::from_utf8_lossy(value).to_string(); 
    s.trim_matches(char::from(0)).to_string() //on supprime les caractères de remplissage null (0x00) qui peuvent être présents
}

///Analyse le payload d'une trame DroneID pour extraire les champs voulus
fn parse_drone_tlv_payload(payload: &[u8]) -> DroneIdFields {
    let mut fields = DroneIdFields::default(); 
    let mut pos = 0usize; 

    while pos + 1 < payload.len() { 
        let tlv_type = payload[pos]; 
        let tlv_len = payload[pos + 1] as usize; 
        if pos + 2 + tlv_len > payload.len() { 
            break;
        }

        //on extrait la valeur du TLV de taille tlv_len à partir de pos+2
        let value = &payload[pos + 2..pos + 2 + tlv_len];
        match tlv_type { //différents types de TLV dans le payload de la trame DroneID selon la doc
            //type 0x01 correspond à la version du protocole, qui doit être de 1 octet et avoir la valeur 1 selon la doc
            0x01 if tlv_len == 1 => fields.protocol_version = Some(value[0]), 
            //type 0x02 correspond à l'ID FR du drone sur 30 octets selon la doc, on convertit les octets de l'ID en chaine de caractères UTF-8
            0x02 if tlv_len == 30 => fields.id_fr = Some(bytes_to_utf8(value)),
            //type 0x03 correspond à l'ID ANSI du drone (numéro de série physique PSN), on accepte n'importe quelle longueur pour cet ID
            0x03 => fields.id_ansi = Some(bytes_to_utf8(value)),
            //type 0x04 correspond à la latitude sur 4 octets codée en entier signé en big-endian
            0x04 if tlv_len == 4 => {
                let raw = i32::from_be_bytes([value[0], value[1], value[2], value[3]]); //convertit les 4 octets de latitude en un entier de 32 bits signé en big-endian
                fields.latitude = Some(raw as f64 / 100_000.0); //latitude avec précision à 5 décimales en divisant par 100000
            }
            //type 0x05 correspond à la longitude sur 4 octets codée en entier signé en big-endian
            0x05 if tlv_len == 4 => {
                let raw = i32::from_be_bytes([value[0], value[1], value[2], value[3]]); 
                fields.longitude = Some(raw as f64 / 100_000.0); 
            }
            //type 0x006 correspond à l'altitude en mètres sur 2 octets en entier signé en big-endian
            0x06 if tlv_len == 2 => {
                fields.altitude_m = Some(i16::from_be_bytes([value[0], value[1]])); //convertit les 2 octets de l'altitude en un entier de 16 bits signé en big-endian
            } 
            //type 0x07 correspond à la hauteur en mètres sur 2 octets en entier signé en big-endian
            0x07 if tlv_len == 2 => {
                fields.height_m = Some(i16::from_be_bytes([value[0], value[1]])); 
            }
            _ => {} //pour les types de TLV non reconnus ou avec une longueur inattendue, on ignore le TLV
        }

        pos += 2 + tlv_len; 
        if pos > payload.len() { 
            break;
        }
    }
    fields
}

/// Analyse un paquet et retourne les détails DroneID si c'est une trame DroneID
fn extract_droneid_info(data: &[u8]) -> Option<String> {
    //récupère la longueur du header Radiotap pour savoir où commence l'en-tête 802.11
    let radiotap_len = get_radiotap_length(data);
    if radiotap_len >= data.len() {
        return None;
    }

    //en-tête 802.11 commence juste après le header Radiotap
    let fc_offset = radiotap_len;
    if fc_offset + 2 > data.len() {
        return None;
    }

    //récupère le frame control pour vérifier le type et le sous-type de la trame
    let frame_control = u16::from_le_bytes([data[fc_offset], data[fc_offset + 1]]);
    let (frame_type, frame_subtype) = get_frame_type_subtype(frame_control);
    if frame_type != 0 || frame_subtype != 8 {
        return None;
    }

    let tlv_offset = fc_offset + 36;

    //extrait les éléments vendor-specific du TLV 
    let vendors = extract_vendor_specific_elements(data, tlv_offset);
    for vendor in vendors {
        if vendor.len() < 4 { //une trame DroneID doit contenir au moins 4 octets dans le payload vendor-specific pour inclure le CID (3 octets) et le type de message (1 octet)
            continue;
        }

        let cid_matches = vendor[0..3] == DRONE_CID; // CID=6A-5C-35 d'après la doc donc on vérifie les 3 premiers octets du payload 
        let vs_type_ok = vendor[3] == 0x01; //type=0x01 d'après la doc donc on vérifie le 4e octet du payload
        if cid_matches && vs_type_ok {
            let payload = &vendor[4..]; //récupère le payload en ignorant les 4 premiers octets 
            let fields = parse_drone_tlv_payload(payload); 

            //on formate les infos extraites pour les afficher, si un champ est absent, on affiche une valeur par défaut 
            let id = fields
                .id_fr
                .clone()
                .or(fields.id_ansi.clone())
                .unwrap_or_else(|| "<ID absent>".to_string());

            let version = fields
                .protocol_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string());
            let lat = fields
                .latitude
                .map(|v| format!("{v:.5}"))
                .unwrap_or_else(|| "?".to_string());
            let lon = fields
                .longitude
                .map(|v| format!("{v:.5}"))
                .unwrap_or_else(|| "?".to_string());

            let z_info = if let Some(alt) = fields.altitude_m {
                format!("alt={}m", alt)
            } else if let Some(h) = fields.height_m {
                format!("h={}m", h)
            } else {
                "z=?".to_string()
            };

            let details = format!("v={} ID='{}' lat={} lon={} {}", version, id, lat, lon, z_info);
            return Some(details);
        }
    }
    None 
}
