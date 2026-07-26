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


#[derive(Deserialize)]
struct CreateUser {
    username: String,
    email: String,
    password: String,
}

async fn create_user(Json(user): Json<CreateUser>) {
    let conn = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )",
        [],
    );
    conn.execute(
        "INSERT INTO users (username, email, password) VALUES (?1, ?2, ?3)",
        (&user.username, &user.email, &user.password),
    );
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