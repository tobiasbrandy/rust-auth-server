use std::str::FromStr;

use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LoginAttemptId(uuid::Uuid);
impl LoginAttemptId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
impl Default for LoginAttemptId {
    fn default() -> Self {
        Self::new()
    }
}
impl AsRef<uuid::Uuid> for LoginAttemptId {
    fn as_ref(&self) -> &uuid::Uuid {
        &self.0
    }
}
impl FromStr for LoginAttemptId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::from_str(s)?))
    }
}
impl std::fmt::Display for LoginAttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TwoFACode(String);
impl TwoFACode {
    pub fn new() -> Self {
        Self(
            rand::rng()
                .random_iter::<char>()
                .take(6)
                .collect::<String>(),
        )
    }
}
impl Default for TwoFACode {
    fn default() -> Self {
        Self::new()
    }
}
impl AsRef<String> for TwoFACode {
    fn as_ref(&self) -> &String {
        &self.0
    }
}
impl FromStr for TwoFACode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 6 {
            Err(format!("Invalid two-factor code length: {}", s.len()))
        } else if !s.chars().all(|c| c.is_ascii_digit()) {
            Err("Invalid two-factor code: must contain only digits".to_string())
        } else {
            Ok(Self(s.to_string()))
        }
    }
}
