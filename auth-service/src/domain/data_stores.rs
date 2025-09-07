use crate::domain::user::User;
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
