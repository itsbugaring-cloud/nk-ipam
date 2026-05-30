use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Olt {
    pub id: i64,
    pub name: String,
    pub ip_address: String,
    pub source_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RouterRecord {
    pub id: i64,
    pub name: String,
    pub wireguard_ip: String,
    pub api_base_url: String,
    pub connection_status: String,
    pub mapped_olt_id: Option<i64>,
    pub last_error: Option<String>,
    pub last_scanned_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IpPoolRecord {
    pub id: i64,
    pub router_id: i64,
    pub pool_name: String,
    pub raw_ranges: String,
    pub derived_network: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplorerRow {
    pub router_id: i64,
    pub device_name: String,
    pub wireguard_ip: String,
    pub olt_name: Option<String>,
    pub olt_ip: Option<String>,
    pub ip_pools: Vec<String>,
    pub connection_status: String,
    pub last_scanned_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRouterRequest {
    pub wireguard_ip: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRouterResponse {
    pub router: ExplorerRow,
    pub matched_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkOlt {
    pub name: String,
    pub ip_address: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterApiPool {
    pub name: String,
    pub ranges: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterApiRoute {
    #[serde(rename = "dst-address")]
    pub dst_address: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportBookmarksResponse {
    pub imported: usize,
}

pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}

