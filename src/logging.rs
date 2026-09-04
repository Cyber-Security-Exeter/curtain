use std::fs::OpenOptions;
use std::io::{BufWriter, Write};

fn Log(message: &str) {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("everything.log").unwrap();
    let mut writer = BufWriter::new(file);
    writer.write_all(message.as_bytes());
    writer.flush();
}

pub fn log_user_page_access(page: &str, user: &str) {
    Log(&format!("{} accessed: {}\n", user, page));
}

pub fn log_login_attempt(user: &str, passhash: &str) {
    Log(&format!("someone attempted to log in as \"{}\" with: \"{}\"\n", user, passhash));
}