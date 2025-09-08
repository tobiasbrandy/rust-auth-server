use std::collections::HashMap;

use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use validator::{Validate, ValidationErrors, ValidationErrorsKind};

#[derive(Debug, Clone)]
pub struct Valid<T>(pub T);
impl<Extractor, T: DeserializeOwned + Validate, S: Send + Sync> FromRequest<S> for Valid<Extractor>
where
    Extractor: FromRequest<S> + std::ops::Deref<Target = T>,
{
    type Rejection = ValidRejection<Extractor::Rejection>;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let extractor = Extractor::from_request(req, state)
            .await
            .map_err(ValidRejection::BodyParsingError)?;

        extractor
            .deref()
            .validate()
            .map_err(|err| ValidRejection::ValidationError(err.into()))?;

        Ok(Valid(extractor))
    }
}

#[derive(Debug)]
pub enum ValidRejection<BodyRejection: IntoResponse> {
    BodyParsingError(BodyRejection),
    ValidationError(ValidationErrorResponse),
}
impl<BodyRejection: IntoResponse> IntoResponse for ValidRejection<BodyRejection> {
    fn into_response(self) -> Response {
        match self {
            ValidRejection::BodyParsingError(e) => e.into_response(),
            ValidRejection::ValidationError(e) => e.into_response(),
        }
    }
}

// ------------ Custom Validation Error Response ------------ //

#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse {
    errors: HashMap<String, ValidationErrorNode>,
}
impl IntoResponse for ValidationErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, axum::extract::Json(self)).into_response()
    }
}
impl From<ValidationErrors> for ValidationErrorResponse {
    fn from(errs: ValidationErrors) -> Self {
        ValidationErrorResponse::from_validation_errors(&errs)
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ValidationErrorNode {
    Messages(Vec<String>),
    Fields(HashMap<String, ValidationErrorNode>),
}

impl ValidationErrorResponse {
    fn from_validation_errors(errors: &ValidationErrors) -> Self {
        let mut map = HashMap::new();

        for (field, kind) in errors.errors() {
            let error = match kind {
                ValidationErrorsKind::Field(field_errors) => {
                    let messages: Vec<String> =
                        field_errors.iter().map(|e| e.to_string()).collect();
                    ValidationErrorNode::Messages(messages)
                }
                ValidationErrorsKind::Struct(nested) => {
                    let nested_map = ValidationErrorResponse::from_validation_errors(nested).errors;
                    ValidationErrorNode::Fields(nested_map)
                }
                ValidationErrorsKind::List(list) => {
                    let mut list_map = HashMap::new();
                    for (idx, nested) in list {
                        let nested_map =
                            ValidationErrorResponse::from_validation_errors(nested).errors;
                        list_map.insert(idx.to_string(), ValidationErrorNode::Fields(nested_map));
                    }
                    ValidationErrorNode::Fields(list_map)
                }
            };
            map.insert(field.to_string(), error);
        }

        ValidationErrorResponse { errors: map }
    }
}
