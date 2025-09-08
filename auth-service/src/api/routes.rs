use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    api::{app_state::AppState, extractors::auth::Authorized, middleware::auth::auth_middleware},
    config,
    models::user::User,
    service::auth::{self, Principal},
};

pub fn api_router(app_state: AppState) -> Router {
    Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/verify-2fa", post(verify_2fa))
        .route("/logout", post(logout))
        .route("/verify-token", post(verify_token))
        .route("/me", get(authed_user))
        .with_state(app_state.clone())
        .layer(middleware::from_fn_with_state(app_state, auth_middleware))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    MissingToken,
    InvalidToken,
    UnexpectedError,
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
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
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

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SignupRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct SignupResponse {
    pub message: String,
}
async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    body.validate()
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    let user = user_store
        .add_user(User {
            email: body.email,
            password: body.password,
            requires_2fa: body.requires_2fa,
        })
        .await
        .map_err(|_| AuthAPIError::UserAlreadyExists)?;

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            message: format!("User {} created successfully!", user.email),
        }),
    ))
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}
async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    body.validate()
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    user_store
        .validate_user(&body.email, &body.password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let auth_token = auth::generate_auth_token(&state.config.auth, &body.email, config::APP_NAME)
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let jar = jar.add(
        cookie::Cookie::build((config::AUTH_TOKEN_COOKIE_NAME, auth_token))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(cookie::SameSite::Lax)
            .max_age(::cookie::time::Duration::seconds(
                auth::JWT_TTL.as_secs().try_into().unwrap(),
            )),
    );

    Ok((StatusCode::OK, jar))
}

async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

async fn logout(
    Authorized(token): Authorized<String>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    state
        .banned_token_store
        .write()
        .await
        .add_token(token.to_string())
        .await;

    let jar = jar.remove(cookie::Cookie::build(config::AUTH_TOKEN_COOKIE_NAME).path("/"));

    (StatusCode::OK, jar)
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
async fn verify_token(
    State(state): State<AppState>,
    Json(body): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    auth::validate_auth_token(
        &state.config.auth,
        &*state.banned_token_store.read().await,
        &body.token,
        config::APP_NAME,
    )
    .await
    .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}

async fn authed_user(
    Authorized(principal): Authorized<Principal>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let user_store = state.user_store.read().await;
    let user = user_store.get_user(&principal.email).await.unwrap();
    (StatusCode::OK, Json(user))
}
