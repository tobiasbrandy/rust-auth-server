use std::collections::{HashMap, hash_map::Entry};

use async_trait::async_trait;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    user::User,
};

#[derive(Debug, Clone, Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<&User, UserStoreError> {
        match self.users.entry(user.email.clone()) {
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
            Entry::Vacant(entry) => Ok(entry.insert(user)),
        }
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.get_user(email).await {
            Ok(user) => {
                if user.password == password {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(
            store.add_user(user).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(store.get_user(&user.email).await, Ok(user));
        assert_eq!(
            store.get_user("nonexistent@example.com").await,
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(
            store.validate_user(&user.email, &user.password).await,
            Ok(())
        );
        assert_eq!(
            store.validate_user(&user.email, "wrong_password").await,
            Err(UserStoreError::InvalidCredentials)
        );
        assert_eq!(
            store
                .validate_user("nonexistent@example.com", &user.password)
                .await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
