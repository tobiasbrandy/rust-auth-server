use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RedisConfig {
    #[validate(length(min = 1))]
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    #[serde(skip_serializing)]
    pub password: SecretString,
    pub namespace: Option<String>,
}

impl RedisConfig {
    fn connection_url(&self) -> String {
        format!(
            "redis://{user}:{password}@{host}:{port}",
            user = self.user.clone().unwrap_or_default(),
            password = self.password.expose_secret(),
            host = self.host,
            port = self.port
        )
    }

    pub async fn build_client(&self) -> Result<RedisClient, redis::RedisError> {
        redis::Client::open(self.connection_url())?
            .get_multiplexed_async_connection()
            .await
            .map(|conn| RedisClient {
                conn,
                namespace: self.namespace.clone(),
            })
    }
}

#[derive(Debug, Clone)]
pub struct RedisClient {
    conn: redis::aio::MultiplexedConnection,
    namespace: Option<String>,
}
impl RedisClient {
    pub fn conn(&self) -> redis::aio::MultiplexedConnection {
        self.conn.clone()
    }

    pub fn key(&self, parts: &[&str]) -> String {
        match self.namespace {
            Some(ref namespace) => format!("{}:{}", namespace, parts.join(":")),
            None => parts.join(":"),
        }
    }
}
