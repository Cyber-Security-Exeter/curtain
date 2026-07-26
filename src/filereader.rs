use std::fs;

pub fn read_file(filename: &str) -> String {
    println!("{}", filename);
    return fs::read_to_string(filename).unwrap();
}