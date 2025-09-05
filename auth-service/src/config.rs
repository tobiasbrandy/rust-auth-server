use std::collections::HashMap;

use config::Config;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::auth;

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AppConfig {
    pub env: AppEnv,
    #[validate(nested)]
    pub auth: auth::AuthConfig,
}

// Could be a separate module/crate
pub fn load_config<'de, T: Deserialize<'de> + Validate>() -> Result<T, Box<dyn std::error::Error>> {
    let env = AppEnv::detect();

    let mut env_vars = std::env::vars().collect::<HashMap<_, _>>();

    if let AppEnv::Dev = env {
        let env_overrides = dotenvy::dotenv_iter()?.collect::<Result<Vec<_>, _>>()?;
        env_vars.extend(env_overrides);
    }

    let config = Config::builder()
        .set_override("env", env.to_string())?
        .add_source(
            config::Environment::default()
                .separator("__")
                .source(Some(env_vars)),
        )
        .build()?
        .try_deserialize::<T>()?;

    config.validate()?;

    Ok(config)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppEnv {
    Dev,
    Prod,
}
impl AppEnv {
    pub fn detect() -> Self {
        match std::env::var("APP_ENV") {
            Ok(env) => env.parse().expect("Invalid APP_ENV"),
            Err(_) => AppEnv::Dev,
        }
    }
}
impl std::fmt::Display for AppEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppEnv::Dev => write!(f, "dev"),
            AppEnv::Prod => write!(f, "prod"),
        }
    }
}
impl std::str::FromStr for AppEnv {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dev" => Ok(AppEnv::Dev),
            "prod" => Ok(AppEnv::Prod),
            s => Err(s.to_owned()),
        }
    }
}
