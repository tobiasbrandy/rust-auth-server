#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
}
