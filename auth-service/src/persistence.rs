pub mod in_memory_2fa_code_store;
pub mod in_memory_banned_token_store;
pub mod in_memory_user_store;
pub mod pg_user_store;
pub mod redis_banned_user_store;

use crate::models::{
    two_fa::{LoginAttemptId, TwoFACode},
    user::User,
};
use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait UserStore: std::fmt::Debug + Send + Sync {
    async fn add_user(
        &self,
        email: String,
        password: String,
        requires_2fa: bool,
    ) -> Result<User, UserStoreError>;

    async fn get_user_by_id(&self, id: i64) -> Result<User, UserStoreError>;

    async fn get_user_by_email(&self, email: &str) -> Result<User, UserStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BannedTokenStoreError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait BannedTokenStore: std::fmt::Debug + Send + Sync {
    async fn add_token(&self, token: String) -> Result<(), BannedTokenStoreError>;

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt id not found")]
    LoginAttemptIdNotFound,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait TwoFACodeStore: std::fmt::Debug + Send + Sync {
    async fn add_code(
        &self,
        email: String,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&self, email: &str) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &str,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}
