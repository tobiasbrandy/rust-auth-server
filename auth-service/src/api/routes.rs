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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    MissingToken,
    InvalidToken,
    UnexpectedError,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    let user = state
        .user_store
        .add_user(body.email, body.password, body.requires_2fa)
        .await
        .map_err(|_| AuthAPIError::UserAlreadyExists)?
        .clone();

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

    if user.password != body.password {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    if user.requires_2fa {
        let login_attempt_id = LoginAttemptId::new();
        let two_fa_code = TwoFACode::new();

        state
            .email_client
            .send_email(&user.email, "2FA required", &login_attempt_id.to_string())
            .await
            .map_err(|_| AuthAPIError::UnexpectedError)?;

        state
            .two_fa_code_store
            .add_code(user.email, login_attempt_id.clone(), two_fa_code)
            .await
            .map_err(|_| AuthAPIError::UnexpectedError)?;

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
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let auth_token = auth::generate_auth_token(&state.config.auth, &body.email, config::APP_NAME)
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let jar = jar.add(auth_cookie(auth_token));

    Ok((StatusCode::OK, jar).into_response())
}

async fn logout(
    Authorized(token): Authorized<String>,
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    state.banned_token_store.add_token(token.to_string()).await;

    let jar = jar.remove(cookie::Cookie::build(config::AUTH_TOKEN_COOKIE_NAME).path("/"));

    (StatusCode::OK, jar)
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
