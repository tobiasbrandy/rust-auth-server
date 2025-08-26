use std::sync::Arc;

use tokio::sync::RwLock;

use crate::services::hashmap_user_store::HashmapUserStore;

#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub user_store: Arc<RwLock<HashmapUserStore>>,
}
