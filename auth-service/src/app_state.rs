use std::sync::Arc;

use tokio::sync::RwLock;

use crate::domain::data_stores::UserStore;

#[derive(Debug, Clone)]
pub struct AppState {
    pub user_store: Arc<RwLock<dyn UserStore>>,
}
impl AppState {
    pub fn new(user_store: impl UserStore + 'static) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(user_store))
        }
    }
}
