use tokio::{self, fs::read};
use axum::{
    routing::get,
    Router,
    Json
};
use axum::http::StatusCode;
use axum::response::Html;
use axum_extra::response::Css;
pub mod filereader;
use filereader::read_file;
use serde::Deserialize;
use rusqlite::{params, Connection, Result};
use rusqlite::fallible_streaming_iterator::FallibleStreamingIterator;
use uuid::Uuid;


#[derive(Deserialize, Debug)]
struct CreateUser {
    username: String,
    email: String,
    password: String,
}

async fn create_user(Json(user): Json<CreateUser>) -> Json<String> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )",
        [],
    ).unwrap();
    let id = Uuid::new_v4();
    let creation_result: Result<usize> = conn.execute(
        "INSERT INTO users (id, username, email, password) VALUES (?1, ?2, ?3, ?4)",
        (format!("{}", id.as_u128()), &user.username, &user.email, &user.password),
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
    Json(format!("{{\"status\": \"ok\", \"jwt\":\"{}\"}}").to_owned())
}


async fn root() -> Html<String> {
    let file = read_file("./pages/welcome.html");
    Html(file)
}

async fn register() -> Html<String> {
    let file = read_file("./pages/register.html");
    Html(file)
}

async fn general() -> Css<String> {
    let file = read_file("./pages/static/general.css");
    Css(file)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/static/general.css", get(general))
        .route("/register", get(register).post(create_user));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}