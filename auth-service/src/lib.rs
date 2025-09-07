pub mod app_state;
pub mod auth;
pub mod config;
pub mod domain;
pub mod routes;
pub mod services;

use axum::{Router, serve::Serve};
use tower_http::services::{ServeDir, ServeFile};

use crate::{app_state::AppState, routes::api_router};

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
