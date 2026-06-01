use std::{env, net::SocketAddr};

use crate::app_error::{AppError, AppResult};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub auth_enabled: bool,
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
    pub session_token: Option<String>,
    pub crypto_key: String,
    pub mikrotik_username: Option<String>,
    pub mikrotik_password: Option<String>,
    pub allow_insecure_tls: bool,
    pub request_timeout_secs: u64,
    pub max_scan_concurrency: usize,
    pub scan_cooldown_secs: u64,
    pub session_ttl_secs: u64,
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

        let admin_username = env::var("APP_ADMIN_USERNAME").ok();
        let admin_password = env::var("APP_ADMIN_PASSWORD").ok();
        let session_token = env::var("APP_SESSION_TOKEN").ok();
        let auth_enabled =
            admin_username.is_some() && admin_password.is_some() && session_token.is_some();
        let crypto_key =
            env::var("APP_CRYPTO_KEY").unwrap_or_else(|_| "replace-with-32-char-secret".to_string());

        Ok(Self {
            bind_addr,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:///app/data/netking.db".to_string()),
            auth_enabled,
            admin_username,
            admin_password,
            session_token,
            crypto_key,
            mikrotik_username: env::var("MIKROTIK_USERNAME").ok(),
            mikrotik_password: env::var("MIKROTIK_PASSWORD").ok(),
            allow_insecure_tls: env::var("MIKROTIK_ALLOW_INSECURE_TLS")
                .unwrap_or_else(|_| "true".to_string())
                .eq_ignore_ascii_case("true"),
            request_timeout_secs: env::var("MIKROTIK_REQUEST_TIMEOUT_SECS")
                .unwrap_or_else(|_| "20".to_string())
                .parse::<u64>()
                .map_err(|err| {
                    AppError::BadRequest(format!("MIKROTIK_REQUEST_TIMEOUT_SECS invalid: {err}"))
                })?,
            max_scan_concurrency: env::var("MAX_SCAN_CONCURRENCY")
                .unwrap_or_else(|_| "8".to_string())
                .parse::<usize>()
                .map_err(|err| {
                    AppError::BadRequest(format!("MAX_SCAN_CONCURRENCY invalid: {err}"))
                })?,
            scan_cooldown_secs: env::var("SCAN_COOLDOWN_SECS")
                .unwrap_or_else(|_| "20".to_string())
                .parse::<u64>()
                .map_err(|err| {
                    AppError::BadRequest(format!("SCAN_COOLDOWN_SECS invalid: {err}"))
                })?,
            session_ttl_secs: env::var("APP_SESSION_TTL_SECS")
                .unwrap_or_else(|_| "43200".to_string())
                .parse::<u64>()
                .map_err(|err| {
                    AppError::BadRequest(format!("APP_SESSION_TTL_SECS invalid: {err}"))
                })?,
        })
    }
}
