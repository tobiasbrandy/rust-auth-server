use auth_service::{
    api::app_state::AppState, config::AppConfig, persistence::{
        in_memory_2fa_code_store::InMemory2FACodeStore,
        in_memory_banned_token_store::InMemoryBannedTokenStore,
        in_memory_user_store::InMemoryUserStore,
    }, service::email::mock_email_client::MockEmailClient, Application
};

#[tokio::main]
async fn main() {
    let app_config = AppConfig::load("APP").expect("Failed to load config");

    let app_state = AppState::new(
        app_config,
        InMemoryUserStore::default(),
        InMemoryBannedTokenStore::default(),
        InMemory2FACodeStore::default(),
        MockEmailClient,
    );

    let app = Application::build("0.0.0.0:80", app_state)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
