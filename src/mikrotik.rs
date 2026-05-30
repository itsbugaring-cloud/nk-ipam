use reqwest::Client;

use crate::{
    app_error::{AppError, AppResult},
    config::AppConfig,
    models::{RouterApiPool, RouterApiRoute},
};

#[derive(Clone)]
pub struct MikrotikClient {
    http: Client,
    username: String,
    password: String,
}

impl MikrotikClient {
    pub fn new(config: &AppConfig) -> AppResult<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(config.allow_insecure_tls)
            .build()?;

        Ok(Self {
            http,
            username: config.mikrotik_username.clone(),
            password: config.mikrotik_password.clone(),
        })
    }

    pub async fn fetch_pools(&self, wireguard_ip: &str) -> AppResult<Vec<RouterApiPool>> {
        self.get_json(&format!("https://{wireguard_ip}/rest/ip/pool")).await
    }

    pub async fn fetch_routes(&self, wireguard_ip: &str) -> AppResult<Vec<RouterApiRoute>> {
        self.get_json(&format!("https://{wireguard_ip}/rest/ip/route")).await
    }

    async fn get_json<T>(&self, url: &str) -> AppResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Upstream(format!(
                "mikrotik API {url} failed with {status}: {body}"
            )));
        }

        Ok(response.json::<T>().await?)
    }
}

