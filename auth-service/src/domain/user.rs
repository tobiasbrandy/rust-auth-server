use validator::Validate;

#[derive(Debug, Clone, Default, PartialEq, Eq, Validate)]
pub struct User {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    pub requires_2fa: bool,
}
