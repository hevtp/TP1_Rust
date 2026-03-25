//! Module `args` : gestion des arguments de ligne de commande
//!
//! Ce module définit la structure `Args` qui permet de parser les arguments via la ligne de commande en utilisant `clap`.
//! On utilise le mode derive car plus lisible et intuitif.
//!
//! Arguments possiblrs :
//! - `--pcap <file>` : fichier PCAP à analyser
//! - `--interface <iface>` : interface réseau pour capture en temps réel
//! - `--cards` : liste les interfaces réseau disponibles
//! - `--filter <filter>` : filtre de capture
//! - `--packet-count <n>` : limite le nombre de paquets analysés
//! - `--output-format <fmt>` : format de sortie (par défaut `json`)
//! - `--output-file <file>` : fichier de sortie (par défaut `results.json`)
//!
//! Il s'agit de la partie 1 du TP.

use clap::{Parser}; //Bibliothèque permettant la gestion des arguments
#[derive(Parser, Debug)]
/// Arguments de ligne de commande du programme.
pub struct Args{
    //Toutes les options sont publiques pour pouvoir les utiliser dans le main
    ///Interface réseau pour capture en temps réel
    /// Incompatible avec --pcap
    #[arg(long, conflicts_with = "pcap")]  //précise l'incompatibilité avec conflicts_with
    pub interface : Option<String>, // Option<String> rend la valeur facultative

    ///Fichier PCAP à analyser
    /// Incompatible avec --interface
    #[clap(long, conflicts_with = "interface")]
    pub pcap : Option<String>,

    ///Affiche la liste des interfaces réseau disponibles puis quitte le programme
    #[arg(long)]
    pub cards : bool,

    /// Filtre de capture à appliquer
    #[clap(long)]
    pub filter : Option<String>,

    /// Filtre de capture à appliquer, par défault 10
    #[clap(long, default_value = "10")]
    pub packet_count : u32,

    /// Format de sortie des résultats, par défault JSON

    #[clap(long, default_value = "json")]
    pub output_format : String,
    /// Nom du fichier de sortie, par défault result.json
    #[clap(long, default_value = "results.json")]
    pub output_file : String,

}
