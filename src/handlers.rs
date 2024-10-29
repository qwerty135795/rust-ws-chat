use std::num::NonZeroU32;
use std::sync::Arc;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use data_encoding::HEXUPPER;
use log::warn;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use ring::{digest, pbkdf2, rand};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use crate::db;
use crate::models::User;

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_owned()
        }
    }
}
#[axum_macros::debug_handler]
pub async fn register(State(pool):State<Arc<Pool<SqliteConnectionManager>>>,
                      Json(user):Json<NewUser>)
    -> impl IntoResponse {
    const CREDENTIAL_LEN:usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let rng = rand::SystemRandom::new();

    let mut salt = [0u8; CREDENTIAL_LEN];
    match rng.fill(&mut salt) {
        Ok(_) => (),
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
    }

    let mut pbkdf_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter, &salt, user.password.as_bytes(), &mut pbkdf_hash
    );
    let user = User::new(&user.username, &user.email, &HEXUPPER.encode(&pbkdf_hash),
                         &HEXUPPER.encode(&salt));
    match db::create_user(user, pool).await {
        Ok(id) => (StatusCode::CREATED, id.to_string()),
        Err(err) => {
            warn!("{}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
    }


#[derive(Debug, Deserialize)]
struct NewUser {
    username: String,
    email:String,
    password:String
}