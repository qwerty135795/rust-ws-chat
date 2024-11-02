use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::{headers, TypedHeader};
use bytes::Bytes;
use chrono::Utc;
use data_encoding::HEXUPPER;
use jsonwebtoken::Header;
use log::{info, warn};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2, rand};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use rmpv::Value;
use socketioxide::extract::{Data, SocketRef};
use crate::models::User;
use crate::{db, Claims, KEYS};
#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_owned(),
        }
    }
}
#[axum_macros::debug_handler]
pub async fn register(
    State(pool): State<Arc<Pool<SqliteConnectionManager>>>,
    Json(user): Json<NewUser>,
) -> impl IntoResponse {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; CREDENTIAL_LEN];
    match rng.fill(&mut salt) {
        Ok(_) => (),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }

    let mut pbkdf_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt,
        user.password.as_bytes(),
        &mut pbkdf_hash,
    );
    let user = User::new(&user.username, &user.email, &pbkdf_hash, &salt);
    match db::create_user(user, pool.clone()).await {
        Ok(id) => (StatusCode::CREATED, id.to_string()),
        Err(err) => {
            warn!("{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
}
#[axum_macros::debug_handler]
pub async fn login(
    State(pool): State<Arc<Pool<SqliteConnectionManager>>>,
    Json(login): Json<Login>,
) -> axum::response::Response {
    let res = tokio::spawn(async move {
        let conn = pool.get().unwrap();
        match conn.query_row(
            "SELECT * from users \
        where username = ?1",
            [login.username],
            |row| {
                Ok::<User, _>(User {
                    id: row.get("id")?,
                    username: row.get("username")?,
                    email: row.get("email")?,
                    password_hash: row.get("password_hash")?,
                    salt: row.get("salt")?,
                    created_at: row.get("created_at")?,
                    is_blocked: row.get("is_blocked")?,
                })
            },
        ) {
            Ok(user) => {
                let n_iter = NonZeroU32::new(100_000).unwrap();
                match pbkdf2::verify(
                    pbkdf2::PBKDF2_HMAC_SHA512,
                    n_iter,
                    &user.salt,
                    login.password.as_bytes(),
                    &user.password_hash,
                ) {
                    Ok(_) => {
                        let claims = Claims {
                            username: user.username,
                            id: user.id.unwrap().to_owned(),
                            exp: (Utc::now().timestamp()
                                + chrono::Duration::minutes(30).num_seconds())
                                as usize,
                        };
                        let token =
                            jsonwebtoken::encode(&Header::default(), &claims, &KEYS.encoding)
                                .unwrap();
                        let auth_body = AuthBody::new(token);
                        (StatusCode::OK, Json(auth_body)).into_response()
                    }
                    Err(err) => {
                        warn!("{}", err);
                        (StatusCode::UNAUTHORIZED, "Wrong password".to_owned()).into_response()
                    }
                }
            }
            Err(err) => {
                warn!("AAA {err}");
                (StatusCode::NOT_FOUND, "User not found".to_owned()).into_response()
            }
        }
    })
    .await;
    res.unwrap_or_else(|err| {
        warn!("{err}");
        (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
    })
}

#[derive(Debug, Deserialize)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct NewUser {
    username: String,
    email: String,
    password: String,
}

pub fn on_connect(socket: SocketRef, Data(value):Data<Value>) {
    tracing::info!(ns = socket.ns(), ?socket.id, "Socket.IO connected");
    socket.emit("auth", &value).ok();
    socket.on("messages", |socket: SocketRef, Data::<Value>(data)| {
        tracing::info!(?data, "Received event");
        socket.emit("message-back", &data).ok();
    })
}


