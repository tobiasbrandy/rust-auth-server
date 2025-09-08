use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{StatusCode, request::Parts},
};

use crate::service::auth::{AuthTokenValidationError, Claims};

#[derive(Debug, Clone)]
pub struct Authorized<T>(pub T);
impl<T, S: Send + Sync> OptionalFromRequestParts<S> for Authorized<T>
where
    Self: From<(Claims, String)>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts
            .extensions
            .remove::<Result<(Claims, String), AuthTokenValidationError>>()
            .transpose()
            .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?
            .map(Self::from))
    }
}
impl<T, S: Send + Sync> FromRequestParts<S> for Authorized<T>
where
    Self: From<(Claims, String)>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        <Self as OptionalFromRequestParts<S>>::from_request_parts(parts, state)
            .await?
            .ok_or((StatusCode::BAD_REQUEST, "Missing token".to_string()))
    }
}

impl From<(Claims, String)> for Authorized<(Claims, String)> {
    fn from((claims, token): (Claims, String)) -> Self {
        Authorized((claims, token))
    }
}
impl<T: From<Claims>> From<(Claims, String)> for Authorized<T> {
    fn from((claims, _): (Claims, String)) -> Self {
        Authorized(claims.into())
    }
}
impl From<(Claims, String)> for Authorized<String> {
    fn from((_, token): (Claims, String)) -> Self {
        Authorized(token)
    }
}
impl From<(Claims, String)> for Authorized<()> {
    fn from(_: (Claims, String)) -> Self {
        Authorized(())
    }
}
