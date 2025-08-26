use auth_service::Application;

#[tokio::main]
async fn main() {
    let app = Application::build("0.0.0.0:3000", Default::default())
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
