use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{app_state::AppState, domain::{error::AuthAPIError, user::User}};

pub fn api_router(app_state: AppState) -> Router {
    Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/verify-2fa", post(verify_2fa))
        .route("/logout", post(logout))
        .route("/verify-token", post(verify_token))
        .with_state(app_state)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
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
) -> Result<impl IntoResponse, AuthAPIError> {
    let user = User {
        email: body.email,
        password: body.password,
        requires_2fa: body.requires_2fa,
    };
    user.validate().map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    // For now, we just assert successful operation
    let user = user_store.add_user(user).await.map_err(|_| AuthAPIError::UserAlreadyExists)?;

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            message: format!("User {} created successfully!", user.email),
        }),
    ))
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
