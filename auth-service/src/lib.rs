pub mod api;
pub mod app_state;
pub mod domain;
pub mod services;

use axum::{Router, serve::Serve};
use tower_http::services::{ServeDir, ServeFile};

use crate::{api::api_router, app_state::AppState};

pub struct Application {
    server: Serve<tokio::net::TcpListener, Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(
        address: &str,
        app_state: AppState,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let router = app_router(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

fn app_router(app_state: AppState) -> Router {
    Router::new()
        .nest_service("/assets", ServeDir::new("assets"))
        .route_service("/", ServeFile::new("assets/index.html"))
        .merge(api_router(app_state))
}
