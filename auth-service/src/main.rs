use auth_service::{
    Application,
    api::app_state::AppState,
    config::AppConfig,
    persistence::{
        pg_user_store::PgUserStore, redis_2fa_code_store::Redis2FACodeStore,
        redis_banned_user_store::RedisBannedUserStore,
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

    let redis = config
        .redis
        .build_client()
        .await
        .expect("Failed to create Redis client");

    let app_state = AppState::new(
        config,
        PgUserStore::new(pg_pool.clone()),
        RedisBannedUserStore::new(redis.clone()),
        Redis2FACodeStore::new(redis.clone()),
        MockEmailClient,
    );

    let app = Application::build(app_state)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
