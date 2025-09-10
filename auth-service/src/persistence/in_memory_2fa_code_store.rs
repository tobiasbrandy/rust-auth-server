use std::collections::HashMap;

use crate::{
    models::two_fa::{LoginAttemptId, TwoFACode},
    persistence::{TwoFACodeStore, TwoFACodeStoreError},
};
use async_trait::async_trait;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemory2FACodeStore {
    codes: HashMap<String, (LoginAttemptId, TwoFACode)>,
}
#[async_trait]
impl TwoFACodeStore for InMemory2FACodeStore {
    async fn add_code(
        &mut self,
        email: String,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &str) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email).map(|_| ()).ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }

    async fn get_code(
        &self,
        email: &str,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes.get(email).cloned().ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_code() {
        let mut store = InMemory2FACodeStore::default();
        let email = "test@example.com".to_string();
        let login_attempt_id = LoginAttemptId::new();
        let code = TwoFACode::new();

        // Test adding a code
        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert!(result.is_ok());

        // Test getting the code
        let get_result = store.get_code(&email).await;
        assert!(get_result.is_ok());
        let (retrieved_id, retrieved_code) = get_result.unwrap();
        assert_eq!(retrieved_id, login_attempt_id);
        assert_eq!(retrieved_code, code);
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let store = InMemory2FACodeStore::default();
        let email = "nonexistent@example.com";

        let result = store.get_code(email).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = InMemory2FACodeStore::default();
        let email = "test@example.com".to_string();
        let login_attempt_id = LoginAttemptId::new();
        let code = TwoFACode::new();

        // Add a code first
        store
            .add_code(email.clone(), login_attempt_id, code)
            .await
            .unwrap();

        // Test removing the code
        let remove_result = store.remove_code(&email).await;
        assert!(remove_result.is_ok());

        // Verify the code is no longer there
        let get_result = store.get_code(&email).await;
        assert!(get_result.is_err());
        assert_eq!(
            get_result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_remove_code_not_found() {
        let mut store = InMemory2FACodeStore::default();
        let email = "nonexistent@example.com";

        let result = store.remove_code(email).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TwoFACodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn test_overwrite_existing_code() {
        let mut store = InMemory2FACodeStore::default();
        let email = "test@example.com".to_string();

        let first_login_attempt_id = LoginAttemptId::new();
        let first_code = TwoFACode::new();

        let second_login_attempt_id = LoginAttemptId::new();
        let second_code = TwoFACode::new();

        // Add first code
        store
            .add_code(email.clone(), first_login_attempt_id, first_code)
            .await
            .unwrap();

        // Add second code (should overwrite the first)
        store
            .add_code(
                email.clone(),
                second_login_attempt_id.clone(),
                second_code.clone(),
            )
            .await
            .unwrap();

        // Verify the second code is retrieved
        let (retrieved_id, retrieved_code) = store.get_code(&email).await.unwrap();
        assert_eq!(retrieved_id, second_login_attempt_id);
        assert_eq!(retrieved_code, second_code);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let mut store = InMemory2FACodeStore::default();

        let email1 = "user1@example.com".to_string();
        let login_attempt_id1 = LoginAttemptId::new();
        let code1 = TwoFACode::new();

        let email2 = "user2@example.com".to_string();
        let login_attempt_id2 = LoginAttemptId::new();
        let code2 = TwoFACode::new();

        // Add codes for both users
        store
            .add_code(email1.clone(), login_attempt_id1.clone(), code1.clone())
            .await
            .unwrap();
        store
            .add_code(email2.clone(), login_attempt_id2.clone(), code2.clone())
            .await
            .unwrap();

        // Verify both codes can be retrieved independently
        let (retrieved_id1, retrieved_code1) = store.get_code(&email1).await.unwrap();
        assert_eq!(retrieved_id1, login_attempt_id1);
        assert_eq!(retrieved_code1, code1);

        let (retrieved_id2, retrieved_code2) = store.get_code(&email2).await.unwrap();
        assert_eq!(retrieved_id2, login_attempt_id2);
        assert_eq!(retrieved_code2, code2);

        // Remove one user's code and verify the other remains
        store.remove_code(&email1).await.unwrap();

        assert!(store.get_code(&email1).await.is_err());
        let (retrieved_id2, retrieved_code2) = store.get_code(&email2).await.unwrap();
        assert_eq!(retrieved_id2, login_attempt_id2);
        assert_eq!(retrieved_code2, code2);
    }
}
