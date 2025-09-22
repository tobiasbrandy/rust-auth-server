use anyhow::Context;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    api::{
        app_state::AppState,
        extractors::{auth::Authorized, validation::Valid},
        middleware::auth::auth_middleware,
    },
    config,
    models::two_fa::{LoginAttemptId, TwoFACode},
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

#[derive(Debug, thiserror::Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Unexpected error")]
    UnexpectedError(#[from] anyhow::Error),
}
impl AuthAPIError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthAPIError::UserAlreadyExists => StatusCode::CONFLICT,
            AuthAPIError::InvalidCredentials => StatusCode::BAD_REQUEST,
            AuthAPIError::MissingToken => StatusCode::BAD_REQUEST,
            AuthAPIError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthAPIError::IncorrectCredentials => StatusCode::UNAUTHORIZED,
            AuthAPIError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: self.to_string(),
        });
        (self.status_code(), body).into_response()
    }
}

pub fn auth_cookie(auth_token: String) -> cookie::Cookie<'static> {
    cookie::Cookie::build((config::AUTH_TOKEN_COOKIE_NAME, auth_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(cookie::SameSite::Lax)
        .max_age(::cookie::time::Duration::seconds(
            auth::JWT_TTL.as_secs().try_into().unwrap(),
        ))
        .build()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct SignupRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
async fn signup(
    State(state): State<AppState>,
    Valid(Json(body)): Valid<Json<SignupRequest>>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let password_hash = tokio::task::spawn_blocking(move || auth::hash_password(&body.password))
        .await
        .context("Failed to hash password")??;

    let user = state
        .user_store
        .add_user(body.email, password_hash, body.requires_2fa)
        .await
        .map_err(|_| AuthAPIError::UserAlreadyExists)?;

    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login2FAResponse {
    pub message: String,
    pub login_attempt_id: LoginAttemptId,
}
async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Valid(Json(body)): Valid<Json<LoginRequest>>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let user = state
        .user_store
        .get_user_by_email(&body.email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    tokio::task::spawn_blocking(move || {
        auth::verify_password(user.password.expose_secret(), &body.password)
    })
    .await
    .context("Failed to verify password")?
    .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    if user.requires_2fa {
        let login_attempt_id = LoginAttemptId::new();
        let two_fa_code = TwoFACode::new();

        state
            .email_client
            .send_email(&user.email, "2FA required", &login_attempt_id.to_string())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        state
            .two_fa_code_store
            .add_code(user.email, login_attempt_id.clone(), two_fa_code)
            .await
            .context("Failed to add 2FA code")?;

        let response = Login2FAResponse {
            message: "2FA required".to_string(),
            login_attempt_id,
        };
        Ok((StatusCode::PARTIAL_CONTENT, Json(response)).into_response())
    } else {
        let auth_token =
            auth::generate_auth_token(&state.config.auth, &body.email, config::APP_NAME).unwrap();

        let jar = jar.add(auth_cookie(auth_token));

        Ok((StatusCode::OK, jar).into_response())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Verify2FARequest {
    pub email: String,
    pub login_attempt_id: LoginAttemptId,
    #[serde(rename = "2FACode")]
    pub code: TwoFACode,
}
async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Valid(Json(body)): Valid<Json<Verify2FARequest>>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let (login_attempt_id, code) = state
        .two_fa_code_store
        .get_code(&body.email)
        .await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    if login_attempt_id != body.login_attempt_id || code != body.code {
        return Err(AuthAPIError::InvalidCredentials);
    }

    state
        .two_fa_code_store
        .remove_code(&body.email)
        .await
        .context("Failed to remove 2FA code")?;

    let auth_token = auth::generate_auth_token(&state.config.auth, &body.email, config::APP_NAME)
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let jar = jar.add(auth_cookie(auth_token));

    Ok((StatusCode::OK, jar).into_response())
}

async fn logout(
    Authorized(token): Authorized<String>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AuthAPIError> {
    state.banned_token_store.add_token(token.to_string()).await.context("Failed to add token")?;

    let jar = jar.remove(cookie::Cookie::build(config::AUTH_TOKEN_COOKIE_NAME).path("/"));

    Ok((StatusCode::OK, jar))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct VerifyTokenRequest {
    pub token: String,
}
async fn verify_token(
    State(state): State<AppState>,
    Valid(Json(body)): Valid<Json<VerifyTokenRequest>>,
) -> Result<impl IntoResponse, AuthAPIError> {
    auth::validate_auth_token(
        &state.config.auth,
        &*state.banned_token_store,
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
    let user = state
        .user_store
        .get_user_by_email(&principal.email)
        .await
        .unwrap();
    (StatusCode::OK, Json(user))
}
