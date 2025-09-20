use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{
    Connection, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct PgConfig {
    #[validate(length(min = 1))]
    pub user: String,
    #[serde(skip_serializing)]
    pub password: SecretString,
    #[validate(length(min = 1))]
    pub host: String,
    pub port: u16,
    #[validate(length(min = 1))]
    pub database: String,
    pub max_connections: u32,
}
impl Default for PgConfig {
    fn default() -> Self {
        Self {
            user: "postgres".to_string(),
            password: "".into(),
            host: "localhost".to_string(),
            port: 5432,
            database: "rust_auth_db".to_string(),
            max_connections: 5,
        }
    }
}
impl PgConfig {
    const PROTOCOL: &'static str = "postgresql";

    pub fn admin_connection_url(&self) -> String {
        format!(
            "{PROTOCOL}://{user}:{password}@{host}:{port}",
            PROTOCOL = Self::PROTOCOL,
            user = self.user,
            password = self.password.expose_secret(),
            host = self.host,
            port = self.port,
        )
    }

    pub fn connection_url(&self) -> String {
        self.admin_connection_url() + "/" + &self.database
    }

    pub fn admin_connection_options(&self) -> PgConnectOptions {
        PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(&self.user)
            .password(self.password.expose_secret())
    }

    pub fn connection_options(&self) -> PgConnectOptions {
        self.admin_connection_options().database(&self.database)
    }

    pub async fn build_connection(&self) -> Result<PgConnection, sqlx::Error> {
        PgConnection::connect_with(&self.connection_options()).await
    }

    pub async fn build_admin_connection(&self) -> Result<PgConnection, sqlx::Error> {
        PgConnection::connect_with(&self.admin_connection_options()).await
    }

    pub async fn build_pool(&self) -> Result<PgPool, sqlx::Error> {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .connect_with(self.connection_options())
            .await
    }

    pub async fn build_admin_pool(&self) -> Result<PgPool, sqlx::Error> {
        PgPoolOptions::new()
            .max_connections(self.max_connections)
            .connect_with(self.admin_connection_options())
            .await
    }
}
