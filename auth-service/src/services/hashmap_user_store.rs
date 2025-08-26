use std::collections::{HashMap, hash_map::Entry};

use crate::domain::user::User;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Debug, Clone, Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<&User, UserStoreError> {
        match self.users.entry(user.email.clone()) {
            Entry::Occupied(_) => Err(UserStoreError::UserAlreadyExists),
            Entry::Vacant(entry) => {
                Ok(entry.insert(user))
            }
        }
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.get_user(email) {
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

    #[test]
    fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).is_ok());
        assert_eq!(store.add_user(user), Err(UserStoreError::UserAlreadyExists));
    }

    #[test]
    fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).is_ok());
        assert_eq!(store.get_user(&user.email), Ok(user));
        assert_eq!(store.get_user("nonexistent@example.com"), Err(UserStoreError::UserNotFound));
    }

    #[test]
    fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User {
            email: "test@example.com".to_string(),
            password: "password".to_string(),
            requires_2fa: false,
        };
        assert!(store.add_user(user.clone()).is_ok());
        assert_eq!(store.validate_user(&user.email, &user.password), Ok(()));
        assert_eq!(store.validate_user(&user.email, "wrong_password"), Err(UserStoreError::InvalidCredentials));
        assert_eq!(store.validate_user("nonexistent@example.com", &user.password), Err(UserStoreError::UserNotFound));
    }
}
