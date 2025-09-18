use std::collections::{HashMap, hash_map::Entry};

use async_trait::async_trait;

use crate::{
    models::user::User,
    persistence::{UserStore, UserStoreError},
};

#[derive(Debug, Clone, Default)]
struct InMemoryuserStoreState {
    users_by_id: HashMap<i64, User>,
    users_by_email: HashMap<String, User>,
    id_gen: i64,
}
#[derive(Debug, Default)]
pub struct InMemoryUserStore(tokio::sync::RwLock<InMemoryuserStoreState>);

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn add_user(
        &self,
        email: String,
        password: String,
        requires_2fa: bool,
    ) -> Result<User, UserStoreError> {
        let mut guard = self.0.write().await;

        let id = guard.id_gen;
        guard.id_gen += 1;

        let user = User {
            id,
            email,
            password,
            requires_2fa,
        };

        match guard.users_by_id.entry(user.id) {
            Entry::Occupied(_) => return Err(UserStoreError::UserAlreadyExists),
            Entry::Vacant(entry) => entry.insert(user.clone()),
        };

        match guard.users_by_email.entry(user.email.clone()) {
            Entry::Occupied(_) => return Err(UserStoreError::UserAlreadyExists),
            Entry::Vacant(entry) => entry.insert(user.clone()),
        };

        Ok(user)
    }

    async fn get_user_by_id(&self, id: i64) -> Result<User, UserStoreError> {
        self.0
            .read()
            .await
            .users_by_id
            .get(&id)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User, UserStoreError> {
        self.0
            .read()
            .await
            .users_by_email
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let store = InMemoryUserStore::default();
        let email = "test@example.com".to_string();
        let password_hash = "password".to_string();

        assert!(
            store
                .add_user(email.clone(), password_hash.clone(), false)
                .await
                .is_ok()
        );
        assert_eq!(
            store.add_user(email, password_hash, false).await,
            Err(UserStoreError::UserAlreadyExists)
        );
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let store = InMemoryUserStore::default();
        let email = "test@example.com".to_string();
        let password_hash = "password".to_string();

        let user = store
            .add_user(email.clone(), password_hash.clone(), false)
            .await
            .unwrap();

        assert_eq!(store.get_user_by_email(&email).await, Ok(user.clone()));
        assert_eq!(
            store.get_user_by_email("nonexistent@example.com").await,
            Err(UserStoreError::UserNotFound)
        );
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let store = InMemoryUserStore::default();
        let email = "test@example.com".to_string();
        let password_hash = "password".to_string();

        let user = store
            .add_user(email.clone(), password_hash.clone(), false)
            .await
            .unwrap();

        assert_eq!(store.get_user_by_id(user.id).await, Ok(user.clone()));
        assert_eq!(
            store.get_user_by_id(user.id + 1).await,
            Err(UserStoreError::UserNotFound)
        );
    }
}
