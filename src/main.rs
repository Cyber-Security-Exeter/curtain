use askama::Template;
use tokio::{self, fs::read};
use axum::{
    response::{
        IntoResponse,
        Response,
        Html,
        Redirect
    },
    routing::{get, post},
    Router,
    Json,
};
use axum_cookie::prelude::*;
use axum::http::StatusCode;
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
use tower_http::services::ServeDir;
use serde_json::json;
use tower::ServiceBuilder;

#[derive(Deserialize, Debug)]
struct CreateUser {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct CreateTeam {
    teamname: String,
    jwt: String,
}

#[derive(Deserialize, Debug)]
struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    uuid: u128,
    username: String,
    permissions: i8,
    exp: u64,
    session_id: u128,
}

#[derive(Serialize, Deserialize, Clone)]
struct AdvancedUser {
    status: String,
    uuid: String,
    username: String,
    teamname: String,
    teamid: String
}

#[derive(Debug, Serialize, Deserialize)]
struct JWT {
    jwt: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct ID {
    id: String
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {err}"),
            )
                .into_response(),
        }
    }
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

fn dbinit() {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    let result = conn.execute(
        "CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY,
            teamname TEXT NOT NULL UNIQUE
        )",
        [],
    );
    let result = conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            permissions INT NOT NULL,
            session_id TEXT UNIQUE,
            team_id TEXT,
            FOREIGN KEY(team_id) REFERENCES teams(id)
        )",
        [],
    );
    conn.close();
}

async fn check_valid_jwt(Json(jwt): Json<JWT>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
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

fn get_user_details_internal(jwt: JWT) -> Option<AdvancedUser> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
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
    if status == "ok" {
        let mut prestmt = conn.prepare("SELECT users.id, users.username, teams.teamname, users.team_id FROM users INNER JOIN teams ON users.team_id = teams.id WHERE users.id=?1");
        let mut stmt = prestmt.unwrap();
        let mut rows = stmt.query_map([format!("{}", decoded_jwt.uuid)], |row| {
            Ok(
                AdvancedUser {
                    status: "ok".to_owned(),
                    uuid: row.get(0)?,
                    username: row.get(1)?,
                    teamname: row.get(2)?,
                    teamid: row.get(3)?,
                }
            )
        });
        match rows {
            Ok(value) => {
                for newuser in value {
                    return Some(newuser.unwrap());
                }
            },
            Err(e) => println!("Error: {}", e),
        }
        println!("bad");
        let mut newprestmt = conn.prepare("SELECT users.id, users.username FROM users WHERE users.id=?1");
        let mut newstmt = newprestmt.unwrap();
        let mut newrows = newstmt.query_map([format!("{}", decoded_jwt.uuid)], |newrow| {
            Ok(
                AdvancedUser {
                    status: "ok".to_owned(),
                    uuid: newrow.get(0)?,
                    username: newrow.get(1)?,
                    teamname: "".to_owned(),
                    teamid: "".to_owned(),
                }
            )
        });
        match newrows {
            Ok(value) => {
                for newuser in value {
                    return Some(newuser.unwrap());
                }
            },
            Err(e) => println!("Error: {}", e),
        }
    }

    None
}

async fn get_user_details(Json(jwt): Json<JWT>) -> impl IntoResponse {
    let user = get_user_details_internal(jwt);
    if user.is_none() {
        return Json("{\"status\": \"bad\"}".to_owned());
    }
    Json(serde_json::to_string(&user.unwrap()).unwrap())
}

async fn create_user(Json(createuser): Json<CreateUser>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let creation_result: Result<usize> = conn.execute(
        "INSERT INTO users (id, username, email, password, permissions, session_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (format!("{}", id.as_u128()), &createuser.username, &createuser.email, &createuser.password, if (createuser.username == "admin") { 1 } else { 0 }, format!("{}", session_id.as_u128())),
    );
    if creation_result.is_err() {
        let mut stmt = conn.prepare("SELECT id FROM users WHERE username=?1 OR email=?2").unwrap();
        let rows = stmt.query([createuser.username.clone(), createuser.email]).unwrap();
        let (size, _) = rows.size_hint();
        if size > 0 as usize {
            return Json("{\"status\": \"email or username is already registered\"}".to_owned());
        }
        return Json("{\"status\": \"email or username is already registered\"}".to_owned());
    }
    let mut user = User {
        uuid: id.as_u128(),
        username: createuser.username.to_owned(),
        permissions: if (createuser.username == "admin") { 1 } else { 0 },
        exp: 0,
        session_id: session_id.as_u128(),
    };
    println!("{}", session_id.as_u128());
    Json(format!("{{\"status\": \"ok\", \"jwt\":\"{}\"}}", create_jwt(&mut user)).to_owned())
}

async fn create_team(Json(createteam): Json<CreateTeam>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let creation_result: Result<usize> = conn.execute(
        "INSERT INTO teams (id, teamname) VALUES (?1, ?2)",
        (format!("{}", id.as_u128()), &createteam.teamname),
    );
    if creation_result.is_err() {
        let mut stmt = conn.prepare("SELECT id FROM teams WHERE teamname=?1").unwrap();
        let rows = stmt.query([createteam.teamname.clone()]).unwrap();
        let (size, _) = rows.size_hint();
        if size > 0 as usize {
            return Json("{\"status\": \"team name is already used\"}".to_owned());
        }
        return Json("{\"status\": \"team name is already used\"}".to_owned());
    }
    let jwtobj = decode_jwt(&(createteam.jwt));
    conn.execute("UPDATE users SET team_id=?1 WHERE username=?2", [format!("{}", id.as_u128()), jwtobj.username]).unwrap();
    Json("{\"status\": \"ok\"}".to_owned())
}

async fn join_team(Json(createteam): Json<CreateTeam>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let jwtobj = decode_jwt(&(createteam.jwt));
    let mut prestmt = conn.prepare("SELECT id FROM teams WHERE teamname=?1");
    let mut stmt = prestmt.unwrap();
    let mut rows = stmt.query_map([createteam.teamname], |row| {
            Ok(
                ID {
                    id: row.get(0)?,
                }
            )
        });
        match rows {
            Ok(value) => {
                for newuser in value {
                    conn.execute("UPDATE users SET team_id=?1 WHERE username=?2", [newuser.unwrap().id, jwtobj.username.clone()]).unwrap();
                    break;
                }
                return Json("{\"status\": \"ok\"}".to_owned());
            },
            Err(e) => {return Json("{\"status\": \"ok\"}".to_owned());},
        }
    
}


async fn login(Json(createuser): Json<Login>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let mut stmt = conn.prepare("SELECT id, permissions FROM users WHERE username=?1 AND password=?2").unwrap();
    let session_id = Uuid::new_v4();
    let mut rows: Vec<User> = stmt.query_map([createuser.username.clone(), createuser.password], |row| {
        println!("{:?}", row);
        Ok(User {
            uuid: row.get::<usize, String>(0).unwrap().parse().unwrap(),
            username: createuser.username.to_owned(),
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

async fn logout_page() -> impl IntoResponse {
    let file = read_file("./templates/logout.html");
    Html(file)
}

async fn logout(Json(jwt): Json<JWT>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let decoded_jwt = decode_jwt(&(jwt.jwt));
    conn.execute("UPDATE users SET session_id=NULL WHERE id=?1", [format!("{}", decoded_jwt.uuid)]).unwrap();
    Json("{\"status\": \"ok\"}".to_owned())
}

async fn get_jwt_details(Json(jwt): Json<JWT>) -> impl IntoResponse {
    let decode_jwt = decode_jwt(&(jwt.jwt));
    Json(((("{\"status\": \"ok\", \"username\": \"".to_owned()) + &(decode_jwt.username)).to_owned() + "\"}").to_owned())
}

async fn root() -> impl IntoResponse {
    let file = read_file("./templates/welcome.html");
    Html(file)
}

async fn home() -> impl IntoResponse {
    let file = read_file("./templates/home.html");
    Html(file)
}

async fn register() -> impl IntoResponse {
    let file = read_file("./templates/register.html");
    Html(file)
}

async fn about() -> impl IntoResponse {
    let file = read_file("./templates/about.html");
    Html(file)
}

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileTemplate {
    username: String,
    teamname: String,
}

async fn profile(cookie: CookieManager) -> Response {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(JWT {jwt : cookie.get("super_secret_dont_touch").unwrap().value().to_owned()});
        println!("test");
        if user.is_some() {
            let template = ProfileTemplate { username: user.clone().unwrap().username, teamname: user.unwrap().teamname};
            return HtmlTemplate(template).into_response();
        }
    }
    Redirect::to("/").into_response()
}

async fn generalcss() -> impl IntoResponse {
    let file = read_file("./templates/static/general.css");
    Css(file)
}

async fn generaljs() -> impl IntoResponse {
    let file = read_file("./templates/static/general.js");
    Css(file)
}

async fn favicon() -> impl IntoResponse {
    axum::response::Html(std::fs::read("./templates/static/icon.ico").unwrap())
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .nest_service("/static/", ServeDir::new("./templates/static"))
        .nest_service("/items/", ServeDir::new("./templates/items"))
        .route("/favicon.ico", get(favicon))
        .route("/home", get(home))
        .route("/profile", get(profile))
        .route("/login", post(login))
        .route("/create_team", post(create_team))
        .route("/join_team", post(join_team))
        .route("/register", get(register).post(create_user))
        .route("/logout", get(logout_page).post(logout))
        .route("/about", get(about))
        .nest_service("/download", ServeDir::new("./templates/downloads"))
        .route("/api/check_valid_jwt", post(check_valid_jwt))
        .route("/api/get_jwt_details", post(get_jwt_details))
        .route("/api/get_user_details", post(get_user_details))
        .layer(CookieLayer::default());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}