use anyhow::Context;
use async_trait::async_trait;
use redis::{AsyncTypedCommands, SetExpiry, SetOptions};

use crate::{
    models::two_fa::{LoginAttemptId, TwoFACode},
    persistence::{TwoFACodeStore, TwoFACodeStoreError},
};

#[derive(Debug, Clone)]
pub struct Redis2FACodeStore {
    redis: crate::redis::RedisClient,
}
impl Redis2FACodeStore {
    const KEY_PREFIX: &str = "2fa_code_store";
    fn key(&self, key: &str) -> String {
        self.redis.key(&[Self::KEY_PREFIX, key])
    }

    pub fn new(redis: crate::redis::RedisClient) -> Self {
        Self { redis }
    }
}

#[async_trait]
impl TwoFACodeStore for Redis2FACodeStore {
    async fn add_code(
        &self,
        email: String,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.redis
            .conn()
            .set_options(
                self.key(&email),
                serde_json::to_string(&(login_attempt_id, code))
                    .context("Failed to serialize 2fa code")?,
                SetOptions::default().with_expiration(SetExpiry::EX(10 * 60)),
            )
            .await
            .context("SET failed")?;
        Ok(())
    }

    async fn remove_code(&self, email: &str) -> Result<(), TwoFACodeStoreError> {
        self.redis
            .conn()
            .del(self.key(email))
            .await
            .context("DEL failed")?;
        Ok(())
    }

    async fn get_code(
        &self,
        email: &str,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let str_code = self
            .redis
            .conn()
            .get(self.key(email))
            .await
            .context("GET failed")?
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        Ok(
            serde_json::from_str::<(LoginAttemptId, TwoFACode)>(&str_code)
                .context("Failed to deserialize 2fa code")?,
        )
    }
}
