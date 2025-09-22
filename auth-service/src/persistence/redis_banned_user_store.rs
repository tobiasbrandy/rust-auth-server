use anyhow::Context;
use async_trait::async_trait;
use redis::{AsyncTypedCommands, SetExpiry, SetOptions};

use crate::persistence::{BannedTokenStore, BannedTokenStoreError};

#[derive(Debug, Clone)]
pub struct RedisBannedUserStore {
    redis: crate::redis::RedisClient,
}
impl RedisBannedUserStore {
    const KEY_PREFIX: &str = "banned_user_store";
    fn key(&self, key: &str) -> String {
        self.redis.key(&[Self::KEY_PREFIX, key])
    }

    pub fn new(redis: crate::redis::RedisClient) -> Self {
        Self { redis }
    }
}

#[async_trait]
impl BannedTokenStore for RedisBannedUserStore {
    async fn add_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        self.redis
            .conn()
            .set_options(
                self.key(&token),
                true,
                SetOptions::default().with_expiration(SetExpiry::EX(60 * 60 * 24 * 30)),
            )
            .await
            .context("SET failed")?;
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self
            .redis
            .conn()
            .exists(self.key(token))
            .await
            .context("EXISTS failed")?)
    }
}
