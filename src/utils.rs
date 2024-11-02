use jsonwebtoken::Validation;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use socketioxide::extract::{Data, SocketRef};
use crate::{Claims, KEYS};

pub fn authentication_middleware(
    s:SocketRef,
    Data(auth): Data<Auth>
) -> Result<(), anyhow::Error> {
    tracing::info!(?auth.access_token);
    let result = jsonwebtoken::decode::<Claims>(&auth.access_token.unwrap(), &KEYS.decoding, &Validation::default())?;
    tracing::info!(?result, "User Auth");
    Ok(())
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Auth {
    #[serde(rename = "auth")]
    access_token:Option<String>
}