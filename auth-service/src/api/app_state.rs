use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    config::AppConfig,
    persistence::{BannedTokenStore, TwoFACodeStore, UserStore}, service::email::EmailClient,
};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<RwLock<dyn UserStore>>,
    pub banned_token_store: Arc<RwLock<dyn BannedTokenStore>>,
    pub two_fa_code_store: Arc<RwLock<dyn TwoFACodeStore>>,
    pub email_client: Arc<dyn EmailClient>,
}
impl AppState {
    pub fn new(
        config: AppConfig,
        user_store: impl UserStore + 'static,
        banned_token_store: impl BannedTokenStore + 'static,
        two_fa_code_store: impl TwoFACodeStore + 'static,
        email_client: impl EmailClient + 'static,
    ) -> Self {
        Self {
            config: Arc::new(config),
            user_store: Arc::new(RwLock::new(user_store)),
            banned_token_store: Arc::new(RwLock::new(banned_token_store)),
            two_fa_code_store: Arc::new(RwLock::new(two_fa_code_store)),
            email_client: Arc::new(email_client),
        }
    }
}
