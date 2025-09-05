#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    MissingToken,
    InvalidToken,
    UnexpectedError,
}
