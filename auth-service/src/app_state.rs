use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{config::AppConfig, domain::data_stores::UserStore};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<RwLock<dyn UserStore>>,
}
impl AppState {
    pub fn new(config: AppConfig, user_store: impl UserStore + 'static) -> Self {
        Self {
            config: Arc::new(config),
            user_store: Arc::new(RwLock::new(user_store)),
        }
    }
}
