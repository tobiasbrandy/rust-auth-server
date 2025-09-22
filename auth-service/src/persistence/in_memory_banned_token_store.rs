use std::collections::HashSet;

use async_trait::async_trait;

use crate::persistence::{BannedTokenStore, BannedTokenStoreError};

#[derive(Debug, Default)]
pub struct InMemoryBannedTokenStore(tokio::sync::RwLock<HashSet<String>>);

#[async_trait]
impl BannedTokenStore for InMemoryBannedTokenStore {
    async fn add_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        self.0.write().await.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.0.read().await.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "test_token".to_string();

        store.add_token(token.clone()).await.unwrap();
        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_token_returns_false_for_non_existent_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "non_existent_token";

        assert!(!store.contains_token(token).await.unwrap());
    }

    #[tokio::test]
    async fn test_store_multiple_tokens() {
        let store = InMemoryBannedTokenStore::default();
        let token1 = "token1".to_string();
        let token2 = "token2".to_string();

        store.add_token(token1.clone()).await.unwrap();
        store.add_token(token2.clone()).await.unwrap();

        assert!(store.contains_token(&token1).await.unwrap());
        assert!(store.contains_token(&token2).await.unwrap());
        assert!(!store.contains_token("token3").await.unwrap());
    }

    #[tokio::test]
    async fn test_store_duplicate_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "duplicate_token".to_string();

        store.add_token(token.clone()).await.unwrap();
        store.add_token(token.clone()).await.unwrap(); // Should not fail

        assert!(store.contains_token(&token).await.unwrap());
    }
}
