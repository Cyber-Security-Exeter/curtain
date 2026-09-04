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
use axum_client_ip::{ClientIp, ClientIpSource};
use sha256::{digest, try_digest};
pub mod authentication;
use authentication::{
    User,
    JWT,
    get_user_details_internal,
    check_valid_jwt_internal,
    decode_jwt,
    create_jwt,
    AdvancedUser,
    is_admin,
    UserExpanded,
    get_users,
    get_user_by_id
};
pub mod logging;
use logging::{
    log_user_page_access,
    log_login_attempt
};

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

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Challenge {
    name: String,
    points: String,
    description: String,
    challengeid: String,
    flag: String,
    linkedfiles: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChallengeButHidden {
    id: String,
    name: String,
    points: i32,
    description: String,
    hidden: bool,
    challengeid: String,
    flag: String,
    linkedfiles: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SetChallengeButHidden {
    id: String,
    hidden: bool
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Flag {
    challengename: String,
    jwt: String,
    flag: String
}


#[derive(Serialize, Deserialize, Clone, Debug)]
struct ID {
    id: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Team {
    name: String,
    points: i32
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MakeAdmin {
    id: String,
    isadmin: bool,
    jwt: String,
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

pub fn dbinit() {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY,
            teamname TEXT NOT NULL UNIQUE
        )",
        [],
    );
    conn.execute(
        "CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            challengename TEXT NOT NULL UNIQUE,
            points INT NOT NULL,
            description TEXT NOT NULL,
            hidden BOOL NOT NULL,
            challengeid TEXT NOT NULL,
            flag TEXT NOT NULL,
            linkedfiles TEXT NOT NULL
        )",
        [],
    );
    conn.execute(
        "CREATE TABLE IF NOT EXISTS challengecompletions (
            id TEXT PRIMARY KEY,
            teamname TEXT NOT NULL,
            challenge TEXT,
            time DATETIME,
            FOREIGN KEY(teamname) REFERENCES teams(teamname),
            FOREIGN KEY(challenge) REFERENCES challenges(challenge_name)
        )",
        [],
    );
    conn.execute(
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
    if (check_valid_jwt_internal(jwt.jwt)) {
        Json("{\"status\": \"ok\"}")
    } else {
        Json("{\"status\": \"bad\"}")
    }
}

fn get_challenges_internal() -> Vec<ChallengeButHidden> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let prestmt = conn.prepare("SELECT id, challengename, points, description, hidden, challengeid, flag, linkedfiles FROM challenges");
    let mut stmt = prestmt.unwrap();
    let rows = stmt.query_map([], |row| {
        Ok(
            ChallengeButHidden {
                id: row.get(0)?,
                name: row.get(1)?,
                points: row.get(2)?,
                description: row.get(3)?,
                hidden: row.get(4)?,
                challengeid: row.get(5)?,
                flag: row.get(6)?,
                linkedfiles: row.get(7)?
            }
        )
    });
    match rows {
        Ok(value) => {
            let mut jsonlist = vec![];
            for row in value {
                if row.is_ok() {
                    jsonlist.push(row.unwrap());
                }
            }
            return jsonlist;
        },
        Err(_) => {;},
    }
    return vec![];
}

async fn set_challenge_hidden(Json(challenge): Json<SetChallengeButHidden>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    conn.execute("UPDATE challenges SET hidden=?1 WHERE id=?2", (challenge.hidden.clone(), challenge.id.clone())).unwrap();
    Json("{\"status\": \"ok\"}")
}

async fn get_challenges() -> impl IntoResponse {
    return Json(serde_json::to_string(&get_challenges_internal()).unwrap());
}


async fn create_challenge(Json(challenge): Json<Challenge>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let creation_result: Result<usize> = conn.execute(
        "INSERT INTO challenges (id, challengename, points, description, hidden, challengeid, flag, linkedfiles) VALUES (?1, ?2, ?3, ?4, true, ?5, ?6, ?7)",
        (format!("{}", id.as_u128()), &challenge.name, &challenge.points, &challenge.description, challenge.challengeid, challenge.flag, challenge.linkedfiles),
    );
    Json("{\"status\": \"ok\"}")
}

fn check_challenge_completion(jwt: JWT, challengename: String) -> bool {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let user = get_user_details_internal(jwt.jwt).unwrap();
    let mut stmt = conn.prepare("SELECT * FROM challengecompletions WHERE challenge=?1 AND teamname=?2").unwrap();
    let rows = stmt.query([challengename, user.teamname]).unwrap();
    let size = rows.count().unwrap();
    if size > 0 as usize {
        return true;
    }
    return false;
}

fn complete_challenge(jwt: JWT, challengename: String) {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let user = get_user_details_internal(jwt.jwt.clone()).unwrap();
    let id = Uuid::new_v4();
    if !check_challenge_completion(jwt, challengename.clone()) {
        conn.execute("INSERT INTO challengecompletions (id, teamname, challenge, time) VALUES (?1, ?2, ?3, date('now'))", [id.as_u128().to_string(), user.teamname, challengename]).unwrap();
    }
}

async fn check_flag(Json(flag): Json<Flag>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let mut stmt = conn.prepare("SELECT * FROM challenges WHERE challengename=?1 AND flag=?2").unwrap();
    let rows = stmt.query([flag.challengename.clone(), flag.flag]).unwrap();
    let size = rows.count().unwrap();
    if size > 0 as usize {
        complete_challenge(JWT { jwt: flag.jwt }, flag.challengename);
        return Json("{\"status\": \"ok\", \"correct\": true}".to_owned());
    }
    return Json("{\"status\": \"ok\", \"correct\": false}".to_owned());

}



async fn make_admin(Json(user): Json<MakeAdmin>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    if (is_admin(user.jwt)) {
        let olduser = get_user_by_id(user.id.clone());
        conn.execute("UPDATE users SET permissions=?1 WHERE id=?2", [if user.isadmin {"1"} else {"0"}, &user.id]).unwrap();
        if (user.isadmin as i32 & 1 == olduser.unwrap().permissions & 1) {
            conn.execute("UPDATE users SET session_id=NULL WHERE id=?1", [user.id]).unwrap();
        }
    }
    return Json("{\"status\": \"ok\"}".to_owned());
}

async fn get_user_details(Json(jwt): Json<JWT>) -> impl IntoResponse {
    let user = get_user_details_internal(jwt.jwt);
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
        (format!("{}", id.as_u128()), &createuser.username, &createuser.email, digest(createuser.password), if (createuser.username == "admin") { 1 } else { 0 }, format!("{}", session_id.as_u128())),
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


fn get_teams() -> Vec<Team> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let query = "
    SELECT teams.teamname, SUM(challenges.points)
    FROM teams
    INNER JOIN challengecompletions
    ON teams.teamname = challengecompletions.teamname 
    INNER JOIN challenges
    ON challenges.challengename = challengecompletions.challenge
    GROUP BY teams.teamname
    ORDER BY SUM(challenges.points) DESC;
    ";
    let mut stmt = conn.prepare(query).unwrap();
    let rows = stmt.query_map([], |row| {
        Ok(
            Team {
                name: row.get(0)?,
                points: row.get(1)?,
            }
        )
    }).unwrap();
    let mut returnvec = vec![];
    for row in rows {
        returnvec.push(row.unwrap());
    }
    returnvec
}


async fn login(Json(createuser): Json<Login>) -> impl IntoResponse {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let mut stmt = conn.prepare("SELECT id, permissions FROM users WHERE username=?1 AND password=?2").unwrap();
    let session_id = Uuid::new_v4();
    let mut rows: Vec<User> = stmt.query_map([createuser.username.clone(), digest(createuser.password.clone())], |row| {
        Ok(User {
            uuid: row.get::<usize, String>(0).unwrap().parse().unwrap(),
            username: createuser.username.to_owned(),
            permissions: row.get::<usize, i8>(1).unwrap(),
            exp: 0,
            session_id: session_id.as_u128(),
        })
    }).unwrap().collect::<Result<Vec<User>, rusqlite::Error>>().unwrap();
    let size = rows.len();
    log_login_attempt(&createuser.username.clone(), &digest(createuser.password));
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

#[derive(askama::Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    challenges: Vec<&'a ChallengeButHidden>,
}

async fn home(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned()).unwrap();
        let mut challenges = get_challenges_internal(); 
        let mut challengecards = vec![];
        for challenge in challenges.iter() {
            if challenge.hidden == false {
                challengecards.push(challenge);
            }
        }
        log_user_page_access("/home", &user.clone().username);
        let template = HomeTemplate { challenges: challengecards};
        return HtmlTemplate(template).into_response();
    }
    log_user_page_access("/home", "none");
    Redirect::to("/").into_response()
}

#[derive(askama::Template)]
#[template(path = "scores.html")]
struct ScoreTemplate<'a> {
    teams: Vec<&'a Team>
}

async fn scores(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned()).unwrap();
        let teams = get_teams();
        let mut refteams = vec![];
        for team in teams.iter() {
            refteams.push(team);
        }
        log_user_page_access("/scores", &user.clone().username);
        let template = ScoreTemplate { teams: refteams };
        return HtmlTemplate(template).into_response();
    }
    log_user_page_access("/scores", "none");
    Redirect::to("/").into_response()
}

async fn register(cookie: CookieManager) -> impl IntoResponse {
    let file = read_file("./templates/register.html");
    Html(file)
}

async fn about(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned()).unwrap();
        let file = read_file("./templates/about.html");
        log_user_page_access("/about", &user.clone().username);
        return Html(file).into_response();
    }
    log_user_page_access("/about", "none");
    Redirect::to("/").into_response()
}

async fn forbidden(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned()).unwrap();
        let file = read_file("./templates/forbidden.html");
        log_user_page_access("/forbidden", &user.clone().username);
        return Html(file).into_response();
    }
    log_user_page_access("/forbidden", "none");
    Redirect::to("/").into_response()
}

#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileTemplate {
    username: String,
    teamname: String,
}

async fn profile(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned());
        if user.is_some() {
            let template = ProfileTemplate { username: user.clone().unwrap().username, teamname: user.clone().unwrap().teamname };
            log_user_page_access("/profile", &user.clone().unwrap().username);
            return HtmlTemplate(template).into_response();
        }
    }
    log_user_page_access("/profile", "none");
    Redirect::to("/").into_response()
}

#[derive(Template)]
#[template(path = "createchallengeadmin.html")]
struct CreateChallengeTemplate {
    username: String,
}

async fn admin_create_challenge(cookie: CookieManager) -> impl IntoResponse {
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned());
        if user.is_some() {
            log_user_page_access("/admin_create_challenge", &user.clone().unwrap().username);
            if (is_admin(cookie.get("super_secret_dont_touch").unwrap().value().to_owned())) {
                let template = CreateChallengeTemplate { username: user.clone().unwrap().username };
                return HtmlTemplate(template).into_response();
            }
            return Redirect::to("/forbidden").into_response();
        }
    }
    log_user_page_access("/admin_create_challenge", "none");
    Redirect::to("/").into_response()
}

#[derive(Template)]
#[template(path = "challengehideradmin.html")]
struct ChallengeHiderTemplate<'a> {
    username: String,
    challenges: Vec<&'a ChallengeButHidden>
}

async fn admin_hide_challenge(cookie: CookieManager) -> impl IntoResponse {
    let mut challenges = get_challenges_internal();
    let mut challengecards = vec![];
    for challenge in challenges.iter() {
        challengecards.push(challenge);
    }
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned());
        if user.is_some() {
            log_user_page_access("/admin_hide_challenge", &user.clone().unwrap().username);
            if (is_admin(cookie.get("super_secret_dont_touch").unwrap().value().to_owned())) {
                let template = ChallengeHiderTemplate { username: user.clone().unwrap().username, challenges: challengecards };
                return HtmlTemplate(template).into_response();
            }
            return Redirect::to("/forbidden").into_response();
        }
    }
    log_user_page_access("/admin_hide_challenge", "none");
    Redirect::to("/").into_response()
}


#[derive(Template)]
#[template(path = "giveadmin.html")]
struct GiveAdminTemplate<'a> {
    users: Vec<&'a UserExpanded>,
}

async fn give_admin(cookie: CookieManager) -> impl IntoResponse {
    let mut users = get_users();
    let mut userrefs = vec![];
    for user in users.iter() {
        userrefs.push(user);
    }
    if cookie.get("super_secret_dont_touch").is_some() {
        let user = get_user_details_internal(cookie.get("super_secret_dont_touch").unwrap().value().to_owned());
        if user.is_some() {
            log_user_page_access("/give_admin", &user.clone().unwrap().username);
            if (is_admin(cookie.get("super_secret_dont_touch").unwrap().value().to_owned())) {
                let template = GiveAdminTemplate { users: userrefs };
                return HtmlTemplate(template).into_response();
            }
            return Redirect::to("/forbidden").into_response();
        }
    }
    log_user_page_access("/give_admin", "none");
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
        .route("/admin/create_challenge", get(admin_create_challenge))
        .route("/admin/hide_challenge", get(admin_hide_challenge))
        .route("/admin/give_admin", get(give_admin))
        .route("/admin", get(|| async { Redirect::to("/admin/create_challenge") }))
        .route("/admin/", get(|| async { Redirect::to("/admin/create_challenge") }))
        .route("/create_team", post(create_team))
        .route("/get_challenges", post(get_challenges))
        .route("/join_team", post(join_team))
        .route("/register", get(register).post(create_user))
        .route("/logout", get(logout_page).post(logout))
        .route("/about", get(about))
        .route("/scores", get(scores))
        .route("/submit_flag", post(check_flag))
        .route("/forbidden", get(forbidden))
        .nest_service("/download", ServeDir::new("./templates/downloads"))
        .route("/api/set_challenge_hidden", post(set_challenge_hidden))
        .route("/api/create_challenge", post(create_challenge))
        .route("/api/make_admin", post(make_admin)) 
        .route("/api/check_valid_jwt", post(check_valid_jwt))
        .route("/api/get_jwt_details", post(get_jwt_details))
        .route("/api/get_user_details", post(get_user_details)) 
        .layer(CookieLayer::default());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}