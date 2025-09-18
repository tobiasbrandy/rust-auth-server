use auth_service::{
    Application,
    api::app_state::AppState,
    config::AppConfig,
    persistence::{
        in_memory_2fa_code_store::InMemory2FACodeStore,
        in_memory_banned_token_store::InMemoryBannedTokenStore, pg_user_store::PgUserStore,
    },
    service::email::mock_email_client::MockEmailClient,
};

#[tokio::main]
async fn main() {
    let config = AppConfig::load("APP").expect("Failed to load config");

    let pg_pool = config
        .db
        .build_pool()
        .await
        .expect("Failed to create Postgresql pool");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    let app_state = AppState::new(
        config,
        PgUserStore::new(pg_pool),
        InMemoryBannedTokenStore::default(),
        InMemory2FACodeStore::default(),
        MockEmailClient,
    );

    let app = Application::build(app_state)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
