
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    pub email: String,
    pub password: String,
    pub requires_2fa: bool,
}
