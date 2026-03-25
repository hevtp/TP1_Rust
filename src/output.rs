//! Module `output` : Enregistrement de la sortie
//!
//! Ce module contient les fonctions nécessaires pour l'affichage dans le terminal et la sauvegarde des résultats dans un fichier JSON ou CSV.
//!
//! Il s'agit de la partie 4 du TP.


use std::fs;
use crate::models::AnalysisResult;


/// Affiche un message dans le terminal et l'ajoute à la liste des lignes pour l'enregistrer dans un fichier JSON à la fin
pub fn log_line(lines: &mut Vec<String>, message: &str) {
    println!("{}", message);
    lines.push(message.to_string());
}

///Fonction permettant de stocker la sortie en JSON ou en CSV.
/// Prend en argument le format de sortie, le chemin du fichier de sortie, et les résultats de l'analyse.
/// Retourne une erreur si le format n'est pas supporté
pub fn save_output(
    format: &str,
    output_file: &str,
    result: &AnalysisResult,
) -> Result<(), Box<dyn std::error::Error>> {
    match format.to_lowercase().as_str() {
        //JSON
        "json" => {
            let json = serde_json::to_string_pretty(result)?; //Sérialise la structure AnalysisResult en JSON avec une mise en forme lisible avec to_string_pretty.
            fs::write(output_file, json)?;//écrit dans le fichier
        }

        //CSV
        "csv" => {
            let mut wtr = csv::Writer::from_path(output_file)?; //Crée un writer CSV vers le fichier de sortie

            // Ecriture de l'entête pour les Beacons et DroneID
            wtr.write_record(["type", "ssid", "mac", "details"])?;

            //Parcours de tous les beacons et écriture dans le CVS
            for b in &result.beacons {
                wtr.write_record(["beacon", &b.ssid, &b.mac, ""])?;
            }
            //Idem les DroneID
            for d in &result.drone_ids {
                wtr.write_record(["drone", "", "", &d.details])?;
            }

            wtr.flush()?; //force l'écriture du buffer dans le fichier
        }

        _ => {
            return Err(format!("Format '{}' non supporté", format).into()); //Format non supporté
        }
    }

    Ok(())
}