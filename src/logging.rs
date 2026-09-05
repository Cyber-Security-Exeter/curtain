use std::fs::OpenOptions;
use std::io::{BufWriter, Write};

fn log(message: &str) {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("everything.log").unwrap();
    let mut writer = BufWriter::new(file);
    writer.write_all(message.as_bytes()).unwrap();
    writer.flush().unwrap();
}

pub fn log_user_page_access(page: &str, user: &str) {
    log(&format!("{} accessed: {}\n", user, page));
}

pub fn log_login_attempt(user: &str, passhash: &str) {
    log(&format!("someone attempted to log in as \"{}\" with: \"{}\"\n", user, passhash));
}

pub fn log_create_user(user: &str, passhash: &str) {
    log(&format!("someone created \"{}\" with password: \"{}\"\n", user, passhash));
}