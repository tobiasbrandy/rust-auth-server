use std::collections::HashSet;

use async_trait::async_trait;

use crate::persistence::BannedTokenStore;

#[derive(Debug, Default)]
pub struct InMemoryBannedTokenStore(tokio::sync::RwLock<HashSet<String>>);

#[async_trait]
impl BannedTokenStore for InMemoryBannedTokenStore {
    async fn add_token(&self, token: String) {
        self.0.write().await.insert(token);
    }

    async fn contains_token(&self, token: &str) -> bool {
        self.0.read().await.contains(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "test_token".to_string();

        store.add_token(token.clone()).await;
        assert!(store.contains_token(&token).await);
    }

    #[tokio::test]
    async fn test_contains_token_returns_false_for_non_existent_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "non_existent_token";

        assert!(!store.contains_token(token).await);
    }

    #[tokio::test]
    async fn test_store_multiple_tokens() {
        let store = InMemoryBannedTokenStore::default();
        let token1 = "token1".to_string();
        let token2 = "token2".to_string();

        store.add_token(token1.clone()).await;
        store.add_token(token2.clone()).await;

        assert!(store.contains_token(&token1).await);
        assert!(store.contains_token(&token2).await);
        assert!(!store.contains_token("token3").await);
    }

    #[tokio::test]
    async fn test_store_duplicate_token() {
        let store = InMemoryBannedTokenStore::default();
        let token = "duplicate_token".to_string();

        store.add_token(token.clone()).await;
        store.add_token(token.clone()).await; // Should not fail

        assert!(store.contains_token(&token).await);
    }
}
