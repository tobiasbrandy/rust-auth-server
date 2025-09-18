use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub requires_2fa: bool,
}
