use std::time::Duration;

use reqwest::Client;

use crate::{
    app_error::{AppError, AppResult},
    config::AppConfig,
    models::{RouterApiPool, RouterApiRoute},
};

#[derive(Clone)]
pub struct MikrotikClient {
    http: Client,
}

impl MikrotikClient {
    pub fn new(config: &AppConfig) -> AppResult<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(config.allow_insecure_tls)
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()?;

        Ok(Self { http })
    }

    pub async fn fetch_pools(
        &self,
        wireguard_ip: &str,
        username: &str,
        password: &str,
    ) -> AppResult<Vec<RouterApiPool>> {
        self.get_json(&format!("https://{wireguard_ip}/rest/ip/pool"), username, password)
            .await
    }

    pub async fn fetch_routes(
        &self,
        wireguard_ip: &str,
        username: &str,
        password: &str,
    ) -> AppResult<Vec<RouterApiRoute>> {
        self.get_json(&format!("https://{wireguard_ip}/rest/ip/route"), username, password)
            .await
    }

    async fn get_json<T>(&self, url: &str, username: &str, password: &str) -> AppResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .get(url)
            .basic_auth(username, Some(password))
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
