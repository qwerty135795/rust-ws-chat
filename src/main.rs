mod db;
mod handlers;
mod models;
mod utils;

use crate::db::init_db;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::routing::post;
use axum::{async_trait, RequestPartsExt, Router};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use env_logger::Env;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use once_cell::sync::Lazy;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::sync::Arc;
use socketioxide::handler::ConnectHandler;
use socketioxide::SocketIo;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init_from_env(Env::new().default_filter_or("info"));
    tracing::subscriber::set_global_default(FmtSubscriber::default()).ok();
    let manager = SqliteConnectionManager::file("chat.db");
    let pool = Arc::new(r2d2::Pool::new(manager).unwrap());
    init_db(pool.clone()).await?;
    let (layer, io) = SocketIo::new_layer();
    io.ns("/", handlers::on_connect.with(utils::authentication_middleware));
    let app = Router::new()
        .route("/user", post(handlers::register))
        .route("/auth", post(handlers::login))
        .layer(layer)
        .layer(CorsLayer::permissive())
        .with_state(pool.clone());
    let listener = TcpListener::bind("127.0.0.1:5000").await?;

    axum::serve(listener, app).await
}

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").unwrap();
    Keys::new(secret.as_bytes())
});

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}
impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    id: i64,
    username: String,
    exp: usize,
}
#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = String;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| "Invalid token")?;

        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| "Invalid token")?;
        Ok(token_data.claims)
    }
}

