use bytes::Bytes;

pub struct User {
    pub id: Option<i64>,
    pub username: String,
    pub email: String,
    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub created_at: Option<i64>,
    pub is_blocked: bool,
}

impl User {
    pub fn new(username: &str, email: &str, password_hash: &[u8], salt: &[u8]) -> Self {
        Self {
            id: None,
            username: username.to_owned(),
            email: email.to_owned(),
            password_hash: password_hash.to_vec(),
            salt: salt.to_vec(),
            created_at: None,
            is_blocked: false,
        }
    }
}
