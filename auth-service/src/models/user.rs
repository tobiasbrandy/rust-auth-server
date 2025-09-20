use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    #[serde(default, skip_serializing)]
    pub password: SecretString,
    pub requires_2fa: bool,
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.email == other.email && self.requires_2fa == other.requires_2fa
    }
}

impl Eq for User {}
