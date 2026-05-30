use std::{env, net::SocketAddr};

use crate::app_error::{AppError, AppResult};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub mikrotik_username: String,
    pub mikrotik_password: String,
    pub allow_insecure_tls: bool,
}

impl AppConfig {
    pub fn from_env() -> AppResult<Self> {
        let host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("APP_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|err| AppError::BadRequest(format!("APP_PORT is invalid: {err}")))?;

        let bind_addr = format!("{host}:{port}")
            .parse::<SocketAddr>()
            .map_err(|err| AppError::BadRequest(format!("APP_HOST/APP_PORT invalid: {err}")))?;

        Ok(Self {
            bind_addr,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://data/netking.db".to_string()),
            mikrotik_username: env::var("MIKROTIK_USERNAME")
                .map_err(|_| AppError::BadRequest("MIKROTIK_USERNAME is required".to_string()))?,
            mikrotik_password: env::var("MIKROTIK_PASSWORD")
                .map_err(|_| AppError::BadRequest("MIKROTIK_PASSWORD is required".to_string()))?,
            allow_insecure_tls: env::var("MIKROTIK_ALLOW_INSECURE_TLS")
                .unwrap_or_else(|_| "true".to_string())
                .eq_ignore_ascii_case("true"),
        })
    }
}

