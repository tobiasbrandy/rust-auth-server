use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::{
    TypedHeader,
    extract::CookieJar,
    headers::{Authorization, authorization::Bearer},
};

use crate::{api::app_state::AppState, config, service};

pub async fn auth_middleware(
    State(state): State<AppState>,
    authorization_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    // Get auth token from authorization header or cookie
    let auth_token = authorization_header
        .map(|header| header.0.token().to_owned())
        .or_else(|| {
            jar.get(config::AUTH_TOKEN_COOKIE_NAME)
                .map(|cookie| cookie.value().to_owned())
        });

    let auth_token = match auth_token {
        Some(token) => token,
        None => return next.run(req).await,
    };

    // Validate auth token
    let claims = service::auth::validate_auth_token(
        &state.config.auth,
        &*state.banned_token_store.read().await,
        &auth_token,
        config::APP_NAME,
    )
    .await
    .map(|claims| (claims, auth_token));

    // Make claims available to handlers
    req.extensions_mut().insert(claims);

    next.run(req).await
}
