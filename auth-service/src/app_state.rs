use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    config::AppConfig,
    domain::data_stores::{BannedTokenStore, UserStore},
};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<RwLock<dyn UserStore>>,
    pub banned_token_store: Arc<RwLock<dyn BannedTokenStore>>,
}
impl AppState {
    pub fn new(
        config: AppConfig,
        user_store: impl UserStore + 'static,
        banned_token_store: impl BannedTokenStore + 'static,
    ) -> Self {
        Self {
            config: Arc::new(config),
            user_store: Arc::new(RwLock::new(user_store)),
            banned_token_store: Arc::new(RwLock::new(banned_token_store)),
        }
    }
}
