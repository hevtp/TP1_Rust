//! # lib.rs
//!
//! Bibliothèque du projet :
//!
//! - models     : contient l'ensemble des structures partagées dans les modules
//! - pcap_analysis : contient l'ensemble des fonctions d'analyse des paquets
//! - output        : sauvegarde les résultats en JSON ou CSV

pub mod args;
pub mod pcap_analysis;

pub mod models;
pub mod output;