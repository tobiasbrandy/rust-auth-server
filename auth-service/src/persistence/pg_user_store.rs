use anyhow::Context;
use async_trait::async_trait;
use sqlx::PgPool;

use crate::{
    models::user::User,
    persistence::{UserStore, UserStoreError},
};

#[derive(Debug, Clone)]
pub struct PgUserStore {
    pool: PgPool,
}

impl PgUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserStore for PgUserStore {
    async fn add_user(
        &self,
        email: String,
        password: String,
        requires_2fa: bool,
    ) -> Result<User, UserStoreError> {
        Ok(sqlx::query_as!(
            User,
            "
            INSERT INTO users (email, password, requires_2fa)
            VALUES ($1, $2, $3)
            RETURNING *
            ",
            email,
            password,
            requires_2fa
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to add user")?)
    }

    async fn get_user_by_id(&self, id: i64) -> Result<User, UserStoreError> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get user by id")?
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User, UserStoreError> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get user by email")?
            .ok_or(UserStoreError::UserNotFound)
    }
}
