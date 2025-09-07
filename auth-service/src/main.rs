use auth_service::{
    Application,
    app_state::AppState,
    config,
    services::{
        hashmap_user_store::HashmapUserStore, hashset_banned_token_store::HashsetBannedTokenStore,
    },
};

#[tokio::main]
async fn main() {
    let app_config = config::load_config("APP").expect("Failed to load config");

    let app_state = AppState::new(
        app_config,
        HashmapUserStore::default(),
        HashsetBannedTokenStore::default(),
    );

    let app = Application::build("0.0.0.0:80", app_state)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
