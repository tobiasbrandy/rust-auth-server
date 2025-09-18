pub mod api;
pub mod config;
pub mod models;
pub mod persistence;
pub mod postgres;
pub mod service;

use axum::{Router, serve::Serve};
use tower_http::services::{ServeDir, ServeFile};

use crate::api::{app_state::AppState, routes::api_router};

pub struct Application {
    server: Serve<tokio::net::TcpListener, Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState) -> Result<Self, Box<dyn std::error::Error>> {
        let config = app_state.config.clone();
        let router = app_router(app_state);

        let listener = tokio::net::TcpListener::bind((config.host.as_str(), config.port)).await?;
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
