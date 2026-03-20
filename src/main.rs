

///TP1 : Analyse de trames réseaux par Agathe Julien et Hevisinda Top

///Objectif : Identifier les trames Wifi d'identification et de localisation de drones et extraire les informations pertinentes de ces trames à l'aide d'un programme en Rust.

/// Partie 1: Arguments de ligne de commande et documentation

/// Cette partie permet de définir et gérer les différents
/// arguments passés au programme en ligne de commande.

///La gestion des arguments est réalisée avec la bibliothèque clap

///On choisit d'utiliser le mode derive car plus lisible et intuitif.

use clap::{Parser};

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
///
/// Dans cette seconde partie, nous analysons le fichier de capture PCAP fourni sur Moodle à l'aide de Wireshark.
/// La capture a été réalisée en mode "monitor" avec une carte Wi-Fi, ce qui permet de capturer toutes les trames présentes dans l’air, y compris les trames de gestion (management frames) et de contrôle.
///
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

/// - **Intervalle de Beacon** : spécifie la durée entre les émissions successives de Beacon.
///  Il permet de savoir à quelle fréquence un client peut s’attendre à recevoir ces trames de balise.

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
///
///
/// Partie 3 : Analyse du fichier PCAP avec Rust.
/// Il s'agit d'écrire un programme en Rust pour analyser ce fichier PCAP et extraire les informations pertinentes de ces trames "beacon" de localisation de drones.

use pcap::Capture;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file("C:/Users/hevis/Downloads/Ressources pour le TP1-20260320/capture-23-05-08-ttgo.pcapng")?;

    while let Ok(packet) = cap.next_packet(){
        println!();
    }
    Ok(())
}
