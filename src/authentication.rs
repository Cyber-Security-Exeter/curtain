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
use crate::read_file;
use serde::{Deserialize, Serialize};
use rusqlite::{params, Connection, Result};
use rusqlite::fallible_streaming_iterator::FallibleStreamingIterator;
use uuid::Uuid;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use serde_json::json;
use crate::dbinit;


#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub uuid: u128,
    pub username: String,
    pub permissions: i8,
    pub exp: u64,
    pub session_id: u128,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWT {
    pub jwt: String,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AdvancedUser {
    pub status: String,
    pub uuid: String,
    pub username: String,
    pub teamname: String,
    pub teamid: String
}

pub fn create_jwt(user: &mut User) -> String {
    let secret = read_file(".env");
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    let timestamp: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    user.exp = timestamp + 60 * 60 * 24 * 7;
    encode(&Header::default(), &user, &encoding_key).unwrap()
}

pub fn decode_jwt(token: &str) -> User {
    let secret = read_file(".env");
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    decode::<User>(token, &decoding_key, &Validation::default()).unwrap().claims
}

pub fn check_valid_jwt_internal(jwt: String) -> bool {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let decoded_jwt = decode_jwt(&(jwt));
    let mut status = true;
    if decoded_jwt.exp <= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
        status = false;
    } else {
        let mut prestmt = conn.prepare("SELECT id, session_id FROM users WHERE id=?1 AND session_id=?2");
        let mut stmt = prestmt.unwrap();
        let mut rows = stmt.query([format!("{}", decoded_jwt.uuid), format!("{}", decoded_jwt.session_id)]).unwrap();
        let mut rowvec = rows.next();
        if !rowvec.is_ok() {
            status = false;
        } else if rowvec.unwrap().is_none() {
            status = false;
        }
    }
    status
}

pub fn get_user_details_internal(jwt: String) -> Option<AdvancedUser> {
    let conn: Connection = Connection::open("userdata.db").unwrap();
    dbinit();
    let decoded_jwt = decode_jwt(&(jwt));
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

pub fn is_admin(jwt: String) -> bool {
    let decoded_jwt = decode_jwt(&(jwt));
    return (decoded_jwt.permissions & 1) == 1;
}