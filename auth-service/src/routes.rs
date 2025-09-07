use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use axum_extra::extract::{CookieJar, cookie};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    app_state::AppState,
    auth,
    domain::{error::AuthAPIError, user::User},
};

pub const DEFAULT_APP: &str = "auth-service";
pub const AUTH_TOKEN_COOKIE_NAME: &str = "__Host-access_token";

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

    let auth_token = auth::generate_auth_token(&state.config.auth, &body.email, DEFAULT_APP)
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let jar = jar.add(
        cookie::Cookie::build((AUTH_TOKEN_COOKIE_NAME, auth_token))
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

async fn logout(state: State<AppState>, jar: CookieJar) -> Result<impl IntoResponse, AuthAPIError> {
    let auth_token = jar
        .get(AUTH_TOKEN_COOKIE_NAME)
        .ok_or(AuthAPIError::MissingToken)?
        .value();

    auth::validate_auth_token(
        &state.config.auth,
        &*state.banned_token_store.read().await,
        auth_token,
        DEFAULT_APP,
    )
    .await
    .map_err(|_| AuthAPIError::InvalidToken)?;

    state
        .banned_token_store
        .write()
        .await
        .add_token(auth_token.to_string())
        .await;

    let jar = jar.remove(cookie::Cookie::build(AUTH_TOKEN_COOKIE_NAME).path("/"));

    Ok((StatusCode::OK, jar))
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct VerifyTokenRequest {
    #[validate(length(min = 1))]
    pub token: String,
}
async fn verify_token(
    State(state): State<AppState>,
    Json(body): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    body.validate().map_err(|_| AuthAPIError::InvalidToken)?;

    auth::validate_auth_token(
        &state.config.auth,
        &*state.banned_token_store.read().await,
        &body.token,
        DEFAULT_APP,
    )
    .await
    .map_err(|_| AuthAPIError::InvalidToken)?;

    Ok(StatusCode::OK)
}
