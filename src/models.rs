//! Module `models` : Structures utilisées
//!
//! Ce module contient les différentes structures utilisées dans les différents modules.
//!
//! On y trouve les structures :
//! - `DroneIdFields` : champs extraits d'une trame DroneID
//! - `AnalysisResult` : résultats complets d'une analyse PCAP
//! - `Beacon` : informations extraites d'une trame beacon Wi-Fi
//! - `Drone` : informations extraites d'une trame DroneID

use serde::Serialize;

///Structure pour stocker les champs extraits d'une trame DroneID, Option gère la présence ou l'absence de chaque champ dans la trame
#[derive(Default)]
pub struct DroneIdFields {
    pub protocol_version: Option<u8>,
    pub id_fr: Option<String>,
    pub id_ansi: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude_m: Option<i16>,
    pub height_m: Option<i16>,
}


/// Structure pour stocker tout les résultats de l'analyse PCAP.
#[derive(Serialize)] /// Sérialisable en JSON/CSV.
pub struct AnalysisResult {
    pub pcap_file: String,
    pub beacons: Vec<Beacon>,
    pub drone_ids: Vec<Drone>,
}
///Structure pour stocker une trame Beacon Wifi
#[derive(Serialize)]
pub struct Beacon {
    pub ssid: String,
    pub mac: String,
}
///Structure pour stocker une trame DroneID
#[derive(Serialize)]
pub struct Drone {
    pub details: String,
}
