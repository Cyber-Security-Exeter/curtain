use tokio::{self, fs::read};
use axum::{
    response::IntoResponse,
    routing::get,
    routing::post,
    Router,
    Json
};
use axum::http::StatusCode;
use axum::response::Html;
use axum_extra::response::Css;
pub mod filereader;
use filereader::read_file;
use serde::{Deserialize, Serialize};
use rusqlite::{params, Connection, Result};
use rusqlite::fallible_streaming_iterator::FallibleStreamingIterator;
use uuid::Uuid;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;


#[derive(Deserialize, Debug)]
struct CreateUser {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    uuid: u128,
    permissions: i8,
    exp: u64,
    session_id: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct JWT {
    jwt: String,
}

fn create_jwt(user: &mut User) -> String {
    let secret = read_file(".env");
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    let timestamp: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    user.exp = timestamp + 60 * 60 * 24 * 7;
    encode(&Header::default(), &user, &encoding_key).unwrap()
}

fn decode_jwt(token: &str) -> User {
    let secret = read_file(".env");
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    decode::<User>(token, &decoding_key, &Validation::default()).unwrap().claims
}

async fn check_valid_jwt(Json(jwt): Json<JWT>) -> Json<String> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            permissions INT NOT NULL,
            session_id TEXT UNIQUE
        )",
        [],
    ).unwrap();
    let decoded_jwt = decode_jwt(&(jwt.jwt));
    let mut status = "ok";
    if decoded_jwt.exp <= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
        status = "bad";
    } else {
        let mut prestmt = conn.prepare("SELECT id, session_id FROM users WHERE id=?1 AND session_id=?2");
        let mut stmt = prestmt.unwrap();
        let mut rows = stmt.query([format!("{}", decoded_jwt.uuid), format!("{}", decoded_jwt.session_id)]).unwrap();
        let mut rowvec = rows.next();
        if !rowvec.is_ok() {
            status = "bad";
        } else if rowvec.unwrap().is_none() {
            status = "bad";
        }
    }
    Json(format!("{{\"status\": \"{}\"}}", status))
}

async fn create_user(Json(user): Json<CreateUser>) -> Json<String> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    let result = conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            permissions INT NOT NULL,
            session_id TEXT UNIQUE
        )",
        [],
    );
    match result {
        Ok(value) => println!("Success: {}", value),
        Err(e) => println!("Error: {}", e),
    }
    let id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let creation_result: Result<usize> = conn.execute(
        "INSERT INTO users (id, username, email, password, permissions, session_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (format!("{}", id.as_u128()), &user.username, &user.email, &user.password, if (user.username == "admin") { 1 } else { 0 }, format!("{}", session_id.as_u128())),
    );
    if creation_result.is_err() {
        let mut stmt = conn.prepare("SELECT id FROM users WHERE username=?1 OR email=?2").unwrap();
        let rows = stmt.query([user.username, user.email]).unwrap();
        let (size, _) = rows.size_hint();
        if size > 0 as usize {
            return Json("{\"status\": \"email or username is already registered\"}".to_owned());
        }
        return Json("{\"status\": \"email or username is already registered\"}".to_owned());
    }
    let mut user = User {
        uuid: id.as_u128(),
        permissions: if (user.username == "admin") { 1 } else { 0 },
        exp: 0,
        session_id: session_id.as_u128(),
    };
    println!("{}", session_id.as_u128());
    Json(format!("{{\"status\": \"ok\", \"jwt\":\"{}\"}}", create_jwt(&mut user)).to_owned())
}


async fn login(Json(user): Json<Login>) -> Json<String> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            permissions INT NOT NULL,
            session_id TEXT UNIQUE
        )",
        [],
    ).unwrap();
    let mut stmt = conn.prepare("SELECT id, permissions FROM users WHERE username=?1 AND password=?2").unwrap();
    let session_id = Uuid::new_v4();
    let mut rows: Vec<User> = stmt.query_map([user.username, user.password], |row| {
        println!("{:?}", row);
        Ok(User {
            uuid: row.get::<usize, String>(0).unwrap().parse().unwrap(),
            permissions: row.get::<usize, i8>(1).unwrap(),
            exp: 0,
            session_id: session_id.as_u128(),
        })
    }).unwrap().collect::<Result<Vec<User>, rusqlite::Error>>().unwrap();
    let size = rows.len();
    if size == 0 {
        return Json("{\"status\": \"username or password incorrect\"}".to_owned());
    }
    conn.execute("UPDATE users SET session_id=?1 WHERE id=?2", [format!("{}", session_id.as_u128()), format!("{}", rows[0].uuid)]).unwrap();
    Json(format!("{{\"status\": \"ok\", \"jwt\":\"{}\"}}", create_jwt(&mut rows[0])).to_owned())
}

async fn logout_page() -> Html<String> {
    let file = read_file("./pages/logout.html");
    Html(file)
}

async fn logout(Json(jwt): Json<JWT>) -> Json<String> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            permissions INT NOT NULL,
            session_id TEXT UNIQUE
        )",
        [],
    ).unwrap();
    let decoded_jwt = decode_jwt(&(jwt.jwt));
    conn.execute("UPDATE users SET session_id=\"0\" WHERE id=?1", [format!("{}", decoded_jwt.uuid)]).unwrap();
    Json("{\"status\": \"ok\"}".to_owned())
}
async fn root() -> Html<String> {
    let file = read_file("./pages/welcome.html");
    Html(file)
}
async fn home() -> Html<String> {
    let file = read_file("./pages/home.html");
    Html(file)
}

async fn register() -> Html<String> {
    let file = read_file("./pages/register.html");
    Html(file)
}

async fn generalcss() -> Css<String> {
    let file = read_file("./pages/static/general.css");
    Css(file)
}

async fn generaljs() -> Css<String> {
    let file = read_file("./pages/static/general.js");
    Css(file)
}

async fn favicon() -> impl IntoResponse {
    axum::response::Html(std::fs::read("./pages/static/icon.ico").unwrap())
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/static/general.css", get(generalcss))
        .route("/static/general.js", get(generaljs))
        .route("/favicon.ico", get(favicon))
        .route("/home", get(home))
        .route("/login", post(login))
        .route("/register", get(register).post(create_user))
        .route("/logout", get(logout_page).post(logout))
        .route("/api/check_valid_jwt", post(check_valid_jwt));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}