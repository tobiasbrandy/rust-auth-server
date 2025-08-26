use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::user::User};

pub fn api_router(app_state: AppState) -> Router {
    Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/verify-2fa", post(verify_2fa))
        .route("/logout", post(logout))
        .route("/verify-token", post(verify_token))
        .with_state(app_state)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}
async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupRequest>,
) -> impl IntoResponse {
    let user = User {
        email: body.email,
        password: body.password,
        requires_2fa: body.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    // For now, we just assert successful operation
    let user = user_store.add_user(user).unwrap();

    (
        StatusCode::CREATED,
        Json(SignupResponse {
            message: format!("User {} created successfully!", user.email),
        }),
    )
}

async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn verify_token() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
