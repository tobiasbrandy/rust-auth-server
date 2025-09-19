use std::collections::HashMap;

use config::Config;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{postgres, service};

pub const APP_NAME: &str = "auth-service";
pub const AUTH_TOKEN_COOKIE_NAME: &str = "__Host-access_token";

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct AppConfig {
    pub env: AppEnv,

    pub domain: String,
    pub host: String,
    pub port: u16,

    #[validate(nested)]
    pub db: postgres::PgConfig,

    #[validate(nested)]
    pub auth: service::auth::AuthConfig,
}
impl AppConfig {
    pub fn load(env_prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        load_config(env_prefix)
    }
}

// Could be a separate module/crate
pub fn load_config<'de, T: Deserialize<'de> + Validate>(
    env_prexif: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let env = AppEnv::detect(env_prexif);

    let env_vars = {
        let mut env_vars = std::env::vars().collect::<HashMap<_, _>>();

        if let AppEnv::Dev | AppEnv::Test = env
            && let Ok(dotenv_iter) = dotenvy::dotenv_iter()
        {
            let env_overrides = dotenv_iter.collect::<Result<Vec<_>, _>>()?;
            env_vars.extend(env_overrides);
        }

        env_vars.insert(format!("{env_prexif}_ENV"), env.to_string());

        env_vars
    };

    let config = Config::builder()
        .add_source(config::File::with_name("config/base"))
        .add_source(config::File::with_name(&format!("config/{env}")).required(false))
        .add_source(config::File::with_name("config/local").required(false))
        .add_source(
            config::Environment::with_prefix(env_prexif)
                .prefix_separator("_")
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
    Test,
    Prod,
}
impl AppEnv {
    pub fn detect(env_prefix: &str) -> Self {
        match std::env::var(format!("{env_prefix}_ENV")) {
            Ok(env) => env
                .parse()
                .unwrap_or_else(|s| panic!("Invalid {env_prefix}_ENV: {s}")),
            Err(_) => AppEnv::Dev,
        }
    }
}
impl std::fmt::Display for AppEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppEnv::Dev => write!(f, "dev"),
            AppEnv::Test => write!(f, "test"),
            AppEnv::Prod => write!(f, "prod"),
        }
    }
}
impl std::str::FromStr for AppEnv {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dev" => Ok(AppEnv::Dev),
            "test" => Ok(AppEnv::Test),
            "prod" => Ok(AppEnv::Prod),
            s => Err(s.to_owned()),
        }
    }
}
