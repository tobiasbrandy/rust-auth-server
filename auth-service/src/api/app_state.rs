use std::sync::Arc;

use crate::{
    config::AppConfig,
    persistence::{BannedTokenStore, TwoFACodeStore, UserStore},
    service::email::EmailClient,
};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub user_store: Arc<dyn UserStore>,
    pub banned_token_store: Arc<dyn BannedTokenStore>,
    pub two_fa_code_store: Arc<dyn TwoFACodeStore>,
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
            user_store: Arc::new(user_store),
            banned_token_store: Arc::new(banned_token_store),
            two_fa_code_store: Arc::new(two_fa_code_store),
            email_client: Arc::new(email_client),
        }
    }
}
