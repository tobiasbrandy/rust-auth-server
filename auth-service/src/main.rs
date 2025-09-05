use auth_service::{
    config, Application, app_state::AppState, services::hashmap_user_store::HashmapUserStore,
};

#[tokio::main]
async fn main() {
    let app_config = config::load_config().expect("Failed to load config");

    let app_state = AppState::new(app_config, HashmapUserStore::default());

    let app = Application::build("0.0.0.0:3000", app_state)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
