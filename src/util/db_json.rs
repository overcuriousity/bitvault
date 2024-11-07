// DISCLAIMER
// (c) 2024-05-27 Mario Stöckl - derived from the original Microbin Project by Daniel Szabo
use std::fs::File;
use std::io;
use std::io::{BufReader, BufWriter};

use crate::Pasta;

static DATABASE_PATH: &str = "pasta_data/database.json";

pub fn read_all() -> Vec<Pasta> {
    load_from_file().expect("Failed to load pastas from JSON")
}

pub fn update_all(pastas: &Vec<Pasta>) {
    save_to_file(pastas);
}

fn save_to_file(pasta_data: &Vec<Pasta>) {
    // This uses a two stage write. First we write to a new file, if this fails
    // only the new pasta's are lost. Then we replace the current database with
    // the new file. This either succeeds or fails. The database is never left
    // in an undefined state.
    let tmp_file_path = DATABASE_PATH.to_string() + ".tmp";
    let tmp_file = File::create(&tmp_file_path).expect(&format!(
        "failed to create temporary database file for writing. path: {tmp_file_path}"
    ));

    let writer = BufWriter::new(tmp_file);
    serde_json::to_writer(writer, &pasta_data)
        .expect("Should be able to write out data to database file");
    std::fs::rename(tmp_file_path, DATABASE_PATH).expect("Could not update database");
}

fn load_from_file() -> io::Result<Vec<Pasta>> {
    let file = File::open(DATABASE_PATH);
    match file {
        Ok(_) => {
            let reader = BufReader::new(file.unwrap());
            let data: Vec<Pasta> = match serde_json::from_reader(reader) {
                Ok(t) => t,
                _ => Vec::new(),
            };
            Ok(data)
        }
        Err(_) => {
            log::info!("Database file {} not found!", DATABASE_PATH);
            save_to_file(&Vec::<Pasta>::new());

            log::info!("Database file {} created.", DATABASE_PATH);
            load_from_file()
        }
    }
}
