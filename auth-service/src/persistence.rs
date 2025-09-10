pub mod in_memory_2fa_code_store;
pub mod in_memory_banned_token_store;
pub mod in_memory_user_store;

use crate::models::{two_fa::{LoginAttemptId, TwoFACode}, user::User};
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait]
pub trait UserStore: std::fmt::Debug + Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<&User, UserStoreError>;

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError>;

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError>;
}

#[async_trait]
pub trait BannedTokenStore: std::fmt::Debug + Send + Sync {
    async fn add_token(&mut self, token: String);

    async fn contains_token(&self, token: &str) -> bool;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[async_trait]
pub trait TwoFACodeStore: std::fmt::Debug + Send + Sync {
    async fn add_code(
        &mut self,
        email: String,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &str) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &str,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}
