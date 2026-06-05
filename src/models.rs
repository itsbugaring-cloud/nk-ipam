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
    pub is_online: Option<bool>,
    pub last_ping_at: Option<String>,
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
    pub is_online: Option<bool>,
    pub last_ping_at: Option<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct ScanRouterResponse {
    pub router: ExplorerRow,
    pub matched_by: Option<String>,
    pub already_existed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkOlt {
    pub name: String,
    pub ip_address: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterApiAddress {
    pub address: String,
    pub interface: String,
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RouterAddressRecord {
    pub id: i64,
    pub router_id: i64,
    pub address: String,
    pub interface: String,
    pub network: Option<String>,
    pub created_at: String,
    pub updated_at: String,
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
    pub is_mapped: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOltRequest {
    pub name: String,
    pub ip_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterDetailResponse {
    pub router: ExplorerRow,
    pub pools: Vec<IpPoolRecord>,
    pub routes: Vec<RouterRouteRecord>,
    pub addresses: Vec<RouterAddressRecord>,
    pub wireguard_interfaces: Vec<WireguardInterfaceRecord>,
    pub wireguard_peers: Vec<WireguardPeerRecord>,
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

// --- WireGuard MikroTik API response types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardApiInterface {
    pub name: String,
    #[serde(rename = "listen-port")]
    pub listen_port: Option<String>,
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "private-key")]
    pub private_key: Option<String>,
    pub mtu: Option<String>,
    pub running: Option<String>,
    pub disabled: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardApiPeer {
    pub interface: Option<String>,
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "endpoint-address")]
    pub endpoint_address: Option<String>,
    #[serde(rename = "endpoint-port")]
    pub endpoint_port: Option<String>,
    #[serde(rename = "allowed-address")]
    pub allowed_address: Option<String>,
    #[serde(rename = "current-endpoint-address")]
    pub current_endpoint_address: Option<String>,
    #[serde(rename = "current-endpoint-port")]
    pub current_endpoint_port: Option<String>,
    #[serde(rename = "last-handshake")]
    pub last_handshake: Option<String>,
    pub rx: Option<String>,
    pub tx: Option<String>,
}

// --- WireGuard database records ---

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WireguardInterfaceRecord {
    pub id: i64,
    pub router_id: i64,
    pub name: String,
    pub listen_port: Option<String>,
    pub public_key: Option<String>,
    pub mtu: Option<String>,
    pub running: bool,
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WireguardPeerRecord {
    pub id: i64,
    pub router_id: i64,
    pub interface_name: Option<String>,
    pub public_key: Option<String>,
    pub endpoint_address: Option<String>,
    pub endpoint_port: Option<String>,
    pub allowed_address: Option<String>,
    pub current_endpoint_address: Option<String>,
    pub current_endpoint_port: Option<String>,
    pub last_handshake: Option<String>,
    pub rx: Option<String>,
    pub tx: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// --- Subnet definitions ---

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SubnetDefinitionRecord {
    pub id: i64,
    pub cidr: String,
    pub label: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSubnetRequest {
    pub cidr: String,
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateSubnetRequest {
    pub cidr: Option<String>,
    pub label: Option<String>,
}

// --- Utilization response types ---

#[derive(Debug, Clone, Serialize)]
pub struct WireguardDataResponse {
    pub interfaces: Vec<WireguardInterfaceRecord>,
    pub peers: Vec<WireguardPeerRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubnetUtilizationResponse {
    pub subnets: Vec<SubnetUtilization>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubnetUtilization {
    pub id: i64,
    pub cidr: String,
    pub label: String,
    pub total_hosts: u64,
    pub used_count: u64,
    pub available_count: u64,
    pub utilization_pct: f64,
    pub used_ips: Vec<UsedIpEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsedIpEntry {
    pub ip: String,
    pub sources: Vec<IpSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpSource {
    pub source_type: String,
    pub router_id: i64,
    pub router_name: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubnetSuggestion {
    pub cidr: String,
    pub proposed_label: String,
    pub source_description: String,
}

pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}
