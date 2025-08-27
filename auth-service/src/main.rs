use auth_service::{app_state::AppState, services::hashmap_user_store::HashmapUserStore, Application};

#[tokio::main]
async fn main() {
    let app = Application::build("0.0.0.0:3000", AppState::new(HashmapUserStore::default()))
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
