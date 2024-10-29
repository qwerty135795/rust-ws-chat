pub struct User {
    pub id: Option<i64>,
    pub username: String,
    pub email: String,
    pub password_hash:String,
    pub salt: String,
    pub created_at: Option<i64>,
    pub is_blocked: bool
}

impl User {
    pub fn new(username:&str, email:&str, password_hash:&str, salt:&str) -> Self {
        Self {
            id: None,
            username: username.to_owned(),
            email: email.to_owned(),
            password_hash: password_hash.to_owned(),
            salt: salt.to_owned(),
            created_at: None,
            is_blocked: false
        }
    }
}