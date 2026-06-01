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
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub auth_source: String,
    pub connection_status: String,
    pub mapped_olt_id: Option<i64>,
    pub mapping_source: Option<String>,
    pub last_error: Option<String>,
    pub last_scanned_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AppSettingRecord {
    pub key: String,
    pub value: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RouterRouteRecord {
    pub id: i64,
    pub router_id: i64,
    pub dst_address: Option<String>,
    pub comment: Option<String>,
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
    pub auth_source: String,
    pub olt_id: Option<i64>,
    pub mapped_by: Option<String>,
    pub olt_name: Option<String>,
    pub olt_ip: Option<String>,
    pub ip_pools: Vec<String>,
    pub connection_status: String,
    pub last_scanned_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplorerResponse {
    pub items: Vec<ExplorerRow>,
    pub page: usize,
    pub per_page: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRouterRequest {
    pub wireguard_ip: String,
    pub device_name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BulkScanRequest {
    pub routers: Vec<ScanRouterRequest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRouterResponse {
    pub router: ExplorerRow,
    pub matched_by: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkScanResponse {
    pub success_count: usize,
    pub failure_count: usize,
    pub results: Vec<BulkScanItemResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkScanItemResult {
    pub wireguard_ip: String,
    pub success: bool,
    pub matched_by: Option<String>,
    pub router: Option<ExplorerRow>,
    pub error: Option<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub default_credentials: bool,
    pub auth_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OltOption {
    pub id: i64,
    pub name: String,
    pub ip_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterDetailResponse {
    pub router: ExplorerRow,
    pub pools: Vec<IpPoolRecord>,
    pub routes: Vec<RouterRouteRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateRouterMappingRequest {
    pub olt_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MikrotikSettingsResponse {
    pub username: Option<String>,
    pub password_configured: bool,
    pub source: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateMikrotikSettingsRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub clear_password: Option<bool>,
    pub clear_username: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}
