use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use axum::extract::State;
use log::{info, warn};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use crate::models::User;

fn create_users_table(pool:Arc<Pool<SqliteConnectionManager>>) -> io::Result<()> {
    let conn = pool.get()
        .expect("Error into create_users_table method");
    let a = conn.execute("CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
  	username VARCHAR(24) NOT NULL,
  	email VARCHAR(36),
  	password_hash BLOB,
    salt BLOB,
  	created_at INTEGER DEFAULT(unixepoch()),
  	is_blocked bool DEFAULT(0)
    )",[]).map_err(|err|io::Error::new(ErrorKind::Other, err))?;
    Ok(())
}
fn create_messages_table(pool:Arc<Pool<SqliteConnectionManager>>) -> io::Result<()> {
    let conn = pool.get().unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS messages (
	id Text PRIMARY KEY NOT NULL,
  	content text,
  	sender_id integer not NULL,
  	receiver_id integer not NULL,
  	FOREIGN KEY(sender_id) REFERENCES users(id),
  	FOREIGN KEY(receiver_id) REFERENCES users(id)
);", []).map_err(|err|io::Error::new(ErrorKind::Other, err))?;
    Ok(())
}
pub async fn init_db(pool:Arc<Pool<SqliteConnectionManager>>) -> io::Result<()> {
    let pool_clone = pool.clone();
    tokio::try_join!(
        async move { create_users_table(pool)},
        async move { create_messages_table(pool_clone)}
    )?;
    Ok(())
}

pub async fn create_user(User {username, email, password_hash, salt, ..}:User, pool: Arc<Pool<SqliteConnectionManager>>) -> io::Result<i64> {
    tokio::spawn(async move {
        let conn = pool.get()
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;
        conn.execute("INSERT INTO users (username, email, password_hash, salt)\
     VALUES (?1, ?2, ?3, ?4)", (&username, &email, &password_hash, &salt))
            .map_err(|err| io::Error::new(ErrorKind::Other, err))?;
        Ok(conn.last_insert_rowid())
    }).await.map_err(|err| io::Error::new(ErrorKind::Other, err))?
}
