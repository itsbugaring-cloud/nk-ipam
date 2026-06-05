use std::{cmp::Reverse, net::IpAddr};

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sqlx::{SqlitePool, Row};
use sha2::Sha256;

use crate::{
    app_error::{AppError, AppResult},
    config::AppConfig,
    crypto,
    mikrotik::MikrotikClient,
    models::{
        now_rfc3339, AuditLog, BookmarkOlt, CreateOltRequest,
        ExplorerResponse, ExplorerRow, HealthResponse, ImportBookmarksResponse, IpPoolRecord, LoginRequest,
        LoginResponse, MikrotikSettingsResponse, OltOption, RouterAddressRecord, RouterApiAddress,
        RouterApiPool, RouterApiRoute, RouterDetailResponse, RouterRecord, RouterRouteRecord,
        ScanRouterRequest, ScanRouterResponse, UpdateMikrotikSettingsRequest, UpdateRouterMappingRequest,
        WireguardApiInterface, WireguardApiPeer, WireguardInterfaceRecord, WireguardPeerRecord,
        SubnetDefinitionRecord, CreateSubnetRequest, UpdateSubnetRequest, WireguardDataResponse,
        SubnetUtilizationResponse, SubnetSuggestion,
    },
    net::{extract_host_ip, parse_scope, ranges_to_scopes, validate_cidr},
    parser::parse_bookmarks_html,
    utilization,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub mikrotik: MikrotikClient,
    pub config: AppConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ExplorerQuery {
    q: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
    status: Option<String>,
    sort_by: Option<String>,
    sort_dir: Option<String>,
}

struct ResolvedCredentials {
    username: String,
    password: String,
    source: String,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/settings/mikrotik", get(get_mikrotik_settings).post(update_mikrotik_settings))
        .route("/api/bookmarks/import", post(import_bookmarks))
        .route("/api/routers/scan", post(scan_router))

        .route("/api/routers/:id/rescan", post(rescan_router))
        .route("/api/routers/:id/map-olt", post(update_router_mapping))
        .route("/api/routers/:id/detail", get(get_router_detail))
        .route("/api/routers/:id/wireguard", get(get_router_wireguard))
        .route("/api/routers/export.csv", get(export_explorer_csv))
        .route("/api/olts", get(list_olts).post(create_olt))
        .route("/api/explorer", get(list_explorer))
        .route("/api/audit-logs", get(list_audit_logs))
        // Subnet routes: literal paths BEFORE parameterized paths
        .route("/api/subnets/utilization", get(get_subnet_utilization))
        .route("/api/subnets/suggestions", get(get_subnet_suggestions))
        .route("/api/subnets", get(list_subnets).post(create_subnet))
        .route("/api/subnets/:id", put(update_subnet).delete(delete_subnet))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> AppResult<Json<HealthResponse>> {
    let database = match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => "ok",
        Err(_) => "error",
    };

    let status = if database == "ok" { "ok" } else { "degraded" }.to_string();

    let (username, password, _) = load_default_mikrotik_credentials(&state.pool, &state.config).await?;

    Ok(Json(HealthResponse {
        status,
        database: database.to_string(),
        default_credentials: username.is_some() && password.is_some(),
        auth_enabled: state.config.auth_enabled,
    }))
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    if !state.config.auth_enabled {
        return Err(AppError::BadRequest(
            "authentication is not enabled in environment".to_string(),
        ));
    }

    let expected_username = state.config.admin_username.as_deref().unwrap_or_default();
    let expected_password = state.config.admin_password.as_deref().unwrap_or_default();

    if payload.username != expected_username || payload.password != expected_password {
        return Err(AppError::Unauthorized);
    }

    let expires_at = Utc::now() + chrono::Duration::seconds(state.config.session_ttl_secs as i64);
    let token = issue_session_token(&state.config, &payload.username, expires_at)?;
    append_audit_log(&state.pool, &payload.username, "login", "session", None, Some("success")).await?;

    Ok(Json(LoginResponse {
        token,
        username: payload.username,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn get_mikrotik_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<MikrotikSettingsResponse>> {
    let _actor = require_auth(&state, &headers)?;
    let (username, password, source) = load_default_mikrotik_credentials(&state.pool, &state.config).await?;

    Ok(Json(MikrotikSettingsResponse {
        username,
        password_configured: password.is_some(),
        source,
    }))
}

async fn update_mikrotik_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateMikrotikSettingsRequest>,
) -> AppResult<Json<MikrotikSettingsResponse>> {
    let actor = require_auth(&state, &headers)?;
    let existing = load_default_mikrotik_credentials(&state.pool, &state.config).await?;
    let username = payload
        .username
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let password = payload
        .password
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let final_username = if payload.clear_username.unwrap_or(false) {
        None
    } else {
        username.or(existing.0)
    };
    upsert_setting(&state.pool, "mikrotik.default_username", final_username.as_deref()).await?;

    if payload.clear_password.unwrap_or(false) {
        upsert_setting(&state.pool, "mikrotik.default_password", None).await?;
    } else if let Some(password) = password.as_deref() {
        let encrypted = crypto::encrypt(&state.config.crypto_key, password)?;
        upsert_setting(&state.pool, "mikrotik.default_password", Some(&encrypted)).await?;
    }

    let response = get_mikrotik_settings(State(state.clone()), headers).await?;
    append_audit_log(
        &state.pool,
        &actor,
        "update_mikrotik_settings",
        "setting",
        None,
        Some("default credentials updated"),
    )
    .await?;

    Ok(response)
}

async fn import_bookmarks(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<Json<ImportBookmarksResponse>> {
    let actor = require_auth(&state, &headers)?;
    let mut imported = 0usize;

    while let Some(field) = multipart.next_field().await? {
        if field.name() != Some("file") {
            continue;
        }

        let content = field.text().await?;
        let records = parse_bookmarks_html(&content)?;
        imported += upsert_olts(&state.pool, &records).await?;
    }

    let detail = format!("imported={imported}");
    append_audit_log(&state.pool, &actor, "import_bookmarks", "olt", None, Some(&detail)).await?;
    Ok(Json(ImportBookmarksResponse { imported }))
}

async fn scan_router(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScanRouterRequest>,
) -> AppResult<Json<ScanRouterResponse>> {
    let actor = require_auth(&state, &headers)?;
    let result = scan_router_payload(&state, payload, false).await?;
    append_audit_log(
        &state.pool,
        &actor,
        "scan_router",
        "router",
        Some(result.router.router_id.to_string()),
        Some(&result.router.wireguard_ip),
    )
    .await?;
    Ok(Json(result))
}


async fn rescan_router(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(router_id): Path<i64>,
) -> AppResult<Json<ScanRouterResponse>> {
    let actor = require_auth(&state, &headers)?;
    let router = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers WHERE id = ?")
        .bind(router_id)
        .fetch_one(&state.pool)
        .await?;

    let payload = ScanRouterRequest {
        wireguard_ip: router.wireguard_ip,
        device_name: Some(router.name),
        username: router.auth_username,
        password: decrypt_router_password(&state.config, router.auth_password)?,
    };

    let response = scan_router_payload(&state, payload, true).await?;
    append_audit_log(
        &state.pool,
        &actor,
        "rescan_router",
        "router",
        Some(router_id.to_string()),
        Some(&response.router.wireguard_ip),
    )
    .await?;

    Ok(Json(response))
}

async fn update_router_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(router_id): Path<i64>,
    Json(payload): Json<UpdateRouterMappingRequest>,
) -> AppResult<Json<ExplorerRow>> {
    let actor = require_auth(&state, &headers)?;

    if let Some(olt_id) = payload.olt_id {
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM olts WHERE id = ?")
            .bind(olt_id)
            .fetch_optional(&state.pool)
            .await?;

        if exists.is_none() {
            return Err(AppError::BadRequest(format!("OLT id {olt_id} not found")));
        }
    }

    sqlx::query(
        r#"
        UPDATE routers
        SET mapped_olt_id = ?, mapping_source = ?, last_error = NULL, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(payload.olt_id)
    .bind(if payload.olt_id.is_some() { "manual" } else { "unmapped" })
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(&state.pool)
    .await?;

    append_audit_log(
        &state.pool,
        &actor,
        "update_mapping",
        "router",
        Some(router_id.to_string()),
        Some(if payload.olt_id.is_some() { "manual" } else { "unmapped" }),
    )
    .await?;

    Ok(Json(fetch_explorer_row(&state.pool, router_id).await?))
}

async fn list_explorer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExplorerQuery>,
) -> AppResult<Json<ExplorerResponse>> {
    let _actor = require_auth(&state, &headers)?;
    Ok(Json(fetch_explorer_rows(&state.pool, &query).await?))
}

async fn export_explorer_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExplorerQuery>,
) -> AppResult<impl IntoResponse> {
    let actor = require_auth(&state, &headers)?;
    let export_query = ExplorerQuery {
        page: Some(1),
        per_page: Some(10_000),
        ..query.clone()
    };
    let rows = fetch_explorer_rows(&state.pool, &export_query).await?.items;

    let mut csv = String::from(
        "device_name,wireguard_ip,auth_source,mapped_by,olt_name,olt_ip,ip_pools,connection_status,last_scanned_at,last_error\n",
    );

    for row in rows {
        let record = [
            csv_escape(&row.device_name),
            csv_escape(&row.wireguard_ip),
            csv_escape(&row.auth_source),
            csv_escape(row.mapped_by.as_deref().unwrap_or("unmapped")),
            csv_escape(row.olt_name.as_deref().unwrap_or("-")),
            csv_escape(row.olt_ip.as_deref().unwrap_or("-")),
            csv_escape(&row.ip_pools.join(" | ")),
            csv_escape(&row.connection_status),
            csv_escape(row.last_scanned_at.as_deref().unwrap_or("-")),
            csv_escape(row.last_error.as_deref().unwrap_or("-")),
        ]
        .join(",");
        csv.push_str(&record);
        csv.push('\n');
    }

    append_audit_log(&state.pool, &actor, "export_csv", "router", None, query.q.as_deref()).await?;

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"netking-ipam-explorer.csv\""),
    );

    Ok((StatusCode::OK, headers, csv))
}

async fn get_router_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(router_id): Path<i64>,
) -> AppResult<Json<RouterDetailResponse>> {
    let _actor = require_auth(&state, &headers)?;
    let router = fetch_explorer_row(&state.pool, router_id).await?;
    let pools = sqlx::query_as::<_, IpPoolRecord>(
        "SELECT * FROM ip_pools WHERE router_id = ? ORDER BY pool_name ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;
    let routes = sqlx::query_as::<_, RouterRouteRecord>(
        "SELECT * FROM router_routes WHERE router_id = ? ORDER BY dst_address ASC, id ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;
    let addresses = sqlx::query_as::<_, RouterAddressRecord>(
        "SELECT * FROM router_addresses WHERE router_id = ? ORDER BY interface ASC, id ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;
    let wireguard_interfaces = sqlx::query_as::<_, WireguardInterfaceRecord>(
        "SELECT * FROM wireguard_interfaces WHERE router_id = ? ORDER BY name ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;
    let wireguard_peers = sqlx::query_as::<_, WireguardPeerRecord>(
        "SELECT * FROM wireguard_peers WHERE router_id = ? ORDER BY interface_name ASC, id ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(RouterDetailResponse { router, pools, routes, addresses, wireguard_interfaces, wireguard_peers }))
}

async fn list_olts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<OltOption>>> {
    let _actor = require_auth(&state, &headers)?;
    let rows = sqlx::query(
        r#"
        SELECT o.id, o.name, o.ip_address, (r.id IS NOT NULL) AS is_mapped
        FROM olts o
        LEFT JOIN routers r ON o.id = r.mapped_olt_id
        ORDER BY o.name ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut olts = Vec::new();
    for row in rows {
        olts.push(OltOption {
            id: row.get("id"),
            name: row.get("name"),
            ip_address: row.get("ip_address"),
            is_mapped: row.get("is_mapped"),
        });
    }

    Ok(Json(olts))
}

async fn create_olt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOltRequest>,
) -> AppResult<Json<OltOption>> {
    let _actor = require_auth(&state, &headers)?;

    let name = payload.name.trim();
    let ip = payload.ip_address.trim();

    if name.is_empty() || ip.is_empty() {
        return Err(AppError::BadRequest("Name and IP address cannot be empty".to_string()));
    }

    let id = sqlx::query(
        "INSERT INTO olts (name, ip_address, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id",
    )
    .bind(name)
    .bind(ip)
    .fetch_one(&state.pool)
    .await?
    .get("id");

    crate::db::log_action(
        &state.pool,
        "api",
        "create_olt",
        &format!("Manually added OLT: {} ({})", name, ip),
    )
    .await;

    Ok(Json(OltOption {
        id,
        name: name.to_string(),
        ip_address: ip.to_string(),
        is_mapped: false,
    }))
}

async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AuditLog>>> {
    let _actor = require_auth(&state, &headers)?;
    let rows = sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn scan_router_payload(
    state: &AppState,
    payload: ScanRouterRequest,
    force: bool,
) -> AppResult<ScanRouterResponse> {
    let wireguard_ip = payload.wireguard_ip.trim().to_string();
    if wireguard_ip.is_empty() {
        return Err(AppError::BadRequest("wireguard_ip is required".to_string()));
    }

    enforce_scan_cooldown(&state.pool, &wireguard_ip, state.config.scan_cooldown_secs, force).await?;

    let device_name = payload
        .device_name
        .clone()
        .unwrap_or_else(|| format!("Router-{wireguard_ip}"));
    let credentials = resolve_credentials(state, &payload).await?;
    let auth_source = credentials.source.as_str();

    let (router_id, already_existed) = upsert_router(
        &state.pool,
        &state.config,
        &device_name,
        &wireguard_ip,
        payload.username.as_deref(),
        payload.password.as_deref(),
        auth_source,
    )
    .await?;

    // Fetch addresses (highest priority data source)
    let addresses = match state
        .mikrotik
        .fetch_addresses(&wireguard_ip, &credentials.username, &credentials.password)
        .await
    {
        Ok(addrs) => addrs,
        Err(err) => {
            mark_router_error(&state.pool, router_id, &err.to_string()).await?;
            return Err(err);
        }
    };

    let pools = match state
        .mikrotik
        .fetch_pools(&wireguard_ip, &credentials.username, &credentials.password)
        .await
    {
        Ok(pools) => pools,
        Err(err) => {
            mark_router_error(&state.pool, router_id, &err.to_string()).await?;
            return Err(err);
        }
    };

    let routes = match state
        .mikrotik
        .fetch_routes(&wireguard_ip, &credentials.username, &credentials.password)
        .await
    {
        Ok(routes) => routes,
        Err(err) => {
            mark_router_error(&state.pool, router_id, &err.to_string()).await?;
            return Err(err);
        }
    };

    replace_router_addresses(&state.pool, router_id, &addresses).await?;
    replace_ip_pools(&state.pool, router_id, &pools).await?;
    replace_router_routes(&state.pool, router_id, &routes).await?;

    // Fetch WireGuard data (non-fatal — graceful degradation)
    let wg_interfaces = match state
        .mikrotik
        .fetch_wireguard_interfaces(&wireguard_ip, &credentials.username, &credentials.password)
        .await
    {
        Ok(ifaces) => ifaces,
        Err(err) => {
            tracing::warn!(router_id, %wireguard_ip, %err, "WireGuard interfaces fetch failed");
            Vec::new()
        }
    };

    let wg_peers = match state
        .mikrotik
        .fetch_wireguard_peers(&wireguard_ip, &credentials.username, &credentials.password)
        .await
    {
        Ok(peers) => peers,
        Err(err) => {
            tracing::warn!(router_id, %wireguard_ip, %err, "WireGuard peers fetch failed");
            Vec::new()
        }
    };

    replace_wireguard_interfaces(&state.pool, router_id, &wg_interfaces).await?;
    replace_wireguard_peers(&state.pool, router_id, &wg_peers).await?;

    let mapping = find_matching_olt(&state.pool, &addresses, &pools, &routes).await?;
    let mapping_source = mapping
        .as_ref()
        .map(|(_, _, reason)| reason.clone())
        .unwrap_or_else(|| "unmapped".to_string());

    sqlx::query(
        r#"
        UPDATE routers
        SET connection_status = ?, mapped_olt_id = ?, mapping_source = ?, last_error = NULL, last_scanned_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind("connected")
    .bind(mapping.as_ref().map(|(id, _, _)| *id))
    .bind(mapping_source)
    .bind(now_rfc3339())
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(&state.pool)
    .await?;

    let explorer_row = fetch_explorer_row(&state.pool, router_id).await?;
    let matched_by = mapping.map(|(_, _, reason)| reason);

    Ok(ScanRouterResponse {
        router: explorer_row,
        matched_by,
        already_existed,
    })
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> AppResult<String> {
    if !state.config.auth_enabled {
        return Ok("anonymous".to_string());
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let Some(token) = auth_header.strip_prefix("Bearer ") else {
        return Err(AppError::Unauthorized);
    };

    validate_session_token(&state.config, token)
}

async fn resolve_credentials(
    state: &AppState,
    payload: &ScanRouterRequest,
) -> AppResult<ResolvedCredentials> {
    if let (Some(username), Some(password)) = (
        payload.username.clone().filter(|value| !value.trim().is_empty()),
        payload.password.clone().filter(|value| !value.trim().is_empty()),
    ) {
        return Ok(ResolvedCredentials {
            username,
            password,
            source: "router".to_string(),
        });
    }

    let (default_username, default_password, source) =
        load_default_mikrotik_credentials(&state.pool, &state.config).await?;
    let username = default_username
        .ok_or_else(|| AppError::BadRequest("default MikroTik username is not configured".to_string()))?;
    let password = default_password
        .ok_or_else(|| AppError::BadRequest("default MikroTik password is not configured".to_string()))?;

    Ok(ResolvedCredentials {
        username,
        password,
        source,
    })
}

fn decrypt_router_password(config: &AppConfig, value: Option<String>) -> AppResult<Option<String>> {
    value.map(|ciphertext| crypto::decrypt(&config.crypto_key, &ciphertext))
        .transpose()
}

async fn enforce_scan_cooldown(
    pool: &SqlitePool,
    wireguard_ip: &str,
    cooldown_secs: u64,
    force: bool,
) -> AppResult<()> {
    if force || cooldown_secs == 0 {
        return Ok(());
    }

    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT last_scanned_at FROM routers WHERE wireguard_ip = ?")
            .bind(wireguard_ip)
            .fetch_optional(pool)
            .await?;

    let Some((Some(last_scanned_at),)) = row else {
        return Ok(());
    };

    let last_scan = DateTime::parse_from_rfc3339(&last_scanned_at)
        .map_err(|err| AppError::Internal(format!("invalid stored timestamp: {err}")))?
        .with_timezone(&Utc);
    let elapsed = Utc::now().signed_duration_since(last_scan).num_seconds();

    if elapsed >= 0 && elapsed < cooldown_secs as i64 {
        return Err(AppError::BadRequest(format!(
            "scan cooldown active for {wireguard_ip}; wait {}s",
            cooldown_secs as i64 - elapsed
        )));
    }

    Ok(())
}

async fn fetch_explorer_rows(pool: &SqlitePool, query: &ExplorerQuery) -> AppResult<ExplorerResponse> {
    let rows = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers")
        .fetch_all(pool)
        .await?;

    let pool_rows = sqlx::query_as::<_, IpPoolRecord>(
        "SELECT * FROM ip_pools ORDER BY router_id ASC, pool_name ASC",
    )
    .fetch_all(pool)
    .await?;
    let olt_rows = sqlx::query_as::<_, crate::models::Olt>("SELECT * FROM olts")
        .fetch_all(pool)
        .await?;

    let mut pools_by_router = std::collections::HashMap::<i64, Vec<String>>::new();
    for pool_row in pool_rows {
        pools_by_router
            .entry(pool_row.router_id)
            .or_default()
            .push(format!("{} ({})", pool_row.pool_name, pool_row.raw_ranges));
    }

    let olt_by_id = olt_rows
        .into_iter()
        .map(|olt| (olt.id, olt))
        .collect::<std::collections::HashMap<_, _>>();

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let olt = row
            .mapped_olt_id
            .and_then(|olt_id| olt_by_id.get(&olt_id));
        items.push(ExplorerRow {
            router_id: row.id,
            device_name: row.name,
            wireguard_ip: row.wireguard_ip,
            auth_source: row.auth_source,
            olt_id: row.mapped_olt_id,
            mapped_by: Some(row.mapping_source.unwrap_or_else(|| "unmapped".to_string())),
            olt_name: olt.map(|item| item.name.clone()),
            olt_ip: olt.map(|item| item.ip_address.clone()),
            ip_pools: pools_by_router.remove(&row.id).unwrap_or_default(),
            connection_status: row.connection_status,
            last_scanned_at: row.last_scanned_at,
            last_error: row.last_error,
            is_online: row.is_online,
            last_ping_at: row.last_ping_at,
        });
    }

    if let Some(status) = query.status.as_deref() {
        let status = status.trim().to_lowercase();
        if !status.is_empty() && status != "all" {
            items.retain(|row| {
                if status == "unmapped" {
                    row.mapped_by.as_deref().unwrap_or("unmapped") == "unmapped"
                } else {
                    row.connection_status.to_lowercase() == status
                }
            });
        }
    }

    if let Some(keyword) = query.q.as_deref() {
        let needle = keyword.trim().to_lowercase();
        if !needle.is_empty() {
            items.retain(|row| {
                let pool_blob = row.ip_pools.join(" ");
                let joined = [
                    row.device_name.as_str(),
                    row.wireguard_ip.as_str(),
                    row.auth_source.as_str(),
                    row.mapped_by.as_deref().unwrap_or(""),
                    row.olt_name.as_deref().unwrap_or(""),
                    row.olt_ip.as_deref().unwrap_or(""),
                    row.connection_status.as_str(),
                    pool_blob.as_str(),
                ]
                .join(" ")
                .to_lowercase();
                joined.contains(&needle)
            });
        }
    }

    let sort_by = query.sort_by.as_deref().unwrap_or("last_scanned_at");
    let sort_desc = query.sort_dir.as_deref().unwrap_or("desc").eq_ignore_ascii_case("desc");

    match (sort_by, sort_desc) {
        ("device_name", false) => items.sort_by(|a, b| a.device_name.cmp(&b.device_name)),
        ("device_name", true) => items.sort_by_key(|row| Reverse(row.device_name.clone())),
        ("wireguard_ip", false) => items.sort_by(|a, b| a.wireguard_ip.cmp(&b.wireguard_ip)),
        ("wireguard_ip", true) => items.sort_by_key(|row| Reverse(row.wireguard_ip.clone())),
        ("status", false) => items.sort_by(|a, b| a.connection_status.cmp(&b.connection_status)),
        ("status", true) => items.sort_by_key(|row| Reverse(row.connection_status.clone())),
        ("olt", false) => items.sort_by(|a, b| a.olt_name.cmp(&b.olt_name)),
        ("olt", true) => items.sort_by_key(|row| Reverse(row.olt_name.clone())),
        ("last_scanned_at", false) => items.sort_by(|a, b| a.last_scanned_at.cmp(&b.last_scanned_at)),
        _ => items.sort_by_key(|row| Reverse(row.last_scanned_at.clone())),
    }

    let total = items.len();
    let per_page = query.per_page.unwrap_or(20).clamp(1, 200);
    let page = query.page.unwrap_or(1).max(1);
    let start = (page - 1) * per_page;
    let end = (start + per_page).min(total);
    let paged_items = if start >= total {
        Vec::new()
    } else {
        items[start..end].to_vec()
    };

    Ok(ExplorerResponse {
        items: paged_items,
        page,
        per_page,
        total,
    })
}

async fn upsert_olts(pool: &SqlitePool, olts: &[BookmarkOlt]) -> AppResult<usize> {
    let mut inserted = 0usize;
    for olt in olts {
        sqlx::query(
            r#"
            INSERT INTO olts (name, ip_address, source_url, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                name = excluded.name,
                source_url = excluded.source_url,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&olt.name)
        .bind(&olt.ip_address)
        .bind(&olt.source_url)
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
        inserted += 1;
    }
    Ok(inserted)
}

async fn upsert_router(
    pool: &SqlitePool,
    config: &AppConfig,
    device_name: &str,
    wireguard_ip: &str,
    auth_username: Option<&str>,
    auth_password: Option<&str>,
    auth_source: &str,
) -> AppResult<(i64, bool)> {
    let scheme = if config.mikrotik_use_https { "https" } else { "http" };
    let api_base_url = format!("{scheme}://{wireguard_ip}/rest");
    let encrypted_password = auth_password
        .map(|password| crypto::encrypt(&config.crypto_key, password))
        .transpose()?;

    // Check if this IP already exists — preserve its name if it does
    let existing: Option<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM routers WHERE wireguard_ip = ?")
            .bind(wireguard_ip)
            .fetch_optional(pool)
            .await?;

    let already_existed = existing.is_some();
    // Keep the existing name unless it's still the auto-generated default
    let final_name = match &existing {
        Some((_, saved_name))
            if saved_name != &format!("Router-{wireguard_ip}") =>
        {
            saved_name.clone()
        }
        _ => device_name.to_string(),
    };

    sqlx::query(
        r#"
        INSERT INTO routers (
            name, wireguard_ip, api_base_url, auth_username, auth_password, auth_source, connection_status, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'connecting', ?)
        ON CONFLICT(wireguard_ip) DO UPDATE SET
            name = excluded.name,
            api_base_url = excluded.api_base_url,
            auth_username = excluded.auth_username,
            auth_password = excluded.auth_password,
            auth_source = excluded.auth_source,
            connection_status = excluded.connection_status,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(final_name)
    .bind(wireguard_ip)
    .bind(api_base_url)
    .bind(auth_username)
    .bind(encrypted_password)
    .bind(auth_source)
    .bind(now_rfc3339())
    .execute(pool)
    .await?;

    let row: (i64,) = sqlx::query_as("SELECT id FROM routers WHERE wireguard_ip = ?")
        .bind(wireguard_ip)
        .fetch_one(pool)
        .await?;
    Ok((row.0, already_existed))
}

pub(crate) async fn replace_router_addresses(
    pool: &SqlitePool,
    router_id: i64,
    addresses: &[RouterApiAddress],
) -> AppResult<()> {
    sqlx::query("DELETE FROM router_addresses WHERE router_id = ?")
        .bind(router_id)
        .execute(pool)
        .await?;

    for addr in addresses {
        sqlx::query(
            r#"
            INSERT INTO router_addresses (router_id, address, interface, network, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(router_id)
        .bind(&addr.address)
        .bind(&addr.interface)
        .bind(&addr.network)
        .bind(now_rfc3339())
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub(crate) async fn replace_ip_pools(pool: &SqlitePool, router_id: i64, pools: &[RouterApiPool]) -> AppResult<()> {
    sqlx::query("DELETE FROM ip_pools WHERE router_id = ?")
        .bind(router_id)
        .execute(pool)
        .await?;

    for item in pools {
        let derived_network = item
            .ranges
            .split(',')
            .find_map(|value| parse_scope(value).map(|scope| match scope {
                crate::net::AddressScope::Cidr(net) => net.to_string(),
                crate::net::AddressScope::Range(start, end) => format!("{start}-{end}"),
            }));

        sqlx::query(
            r#"
            INSERT INTO ip_pools (router_id, pool_name, raw_ranges, derived_network, updated_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(router_id)
        .bind(&item.name)
        .bind(&item.ranges)
        .bind(derived_network)
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub(crate) async fn replace_router_routes(
    pool: &SqlitePool,
    router_id: i64,
    routes: &[RouterApiRoute],
) -> AppResult<()> {
    sqlx::query("DELETE FROM router_routes WHERE router_id = ?")
        .bind(router_id)
        .execute(pool)
        .await?;

    for route in routes {
        sqlx::query(
            r#"
            INSERT INTO router_routes (router_id, dst_address, comment, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(router_id)
        .bind(&route.dst_address)
        .bind(&route.comment)
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn find_matching_olt(
    pool: &SqlitePool,
    addresses: &[RouterApiAddress],
    pools: &[RouterApiPool],
    routes: &[RouterApiRoute],
) -> AppResult<Option<(i64, String, String)>> {
    let olts = sqlx::query_as::<_, crate::models::Olt>("SELECT * FROM olts")
        .fetch_all(pool)
        .await?;

    // Priority 1: Match against interface addresses
    let interface_ips: Vec<IpAddr> = addresses
        .iter()
        .filter_map(|entry| extract_host_ip(&entry.address))
        .collect();

    for olt in &olts {
        let ip = match olt.ip_address.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        if interface_ips.contains(&ip) {
            return Ok(Some((olt.id, olt.ip_address.clone(), "auto_address".to_string())));
        }
    }

    // Priority 2: Match against route dst-addresses
    let route_scopes: Vec<_> = routes
        .iter()
        .filter_map(|route| route.dst_address.as_deref())
        .filter_map(parse_scope)
        .collect();

    for olt in &olts {
        let ip = match olt.ip_address.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        if route_scopes.iter().any(|scope| scope.contains_ip(ip)) {
            return Ok(Some((olt.id, olt.ip_address.clone(), "auto_route".to_string())));
        }
    }

    // Priority 3: Match against pool ranges
    let pool_scopes: Vec<_> = pools
        .iter()
        .flat_map(|item| ranges_to_scopes(&item.ranges))
        .collect();

    for olt in olts {
        let ip = match olt.ip_address.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        if pool_scopes.iter().any(|scope| scope.contains_ip(ip)) {
            return Ok(Some((olt.id, olt.ip_address.clone(), "auto_pool".to_string())));
        }
    }

    Ok(None)
}

async fn fetch_explorer_row(pool: &SqlitePool, router_id: i64) -> AppResult<ExplorerRow> {
    let router = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers WHERE id = ?")
        .bind(router_id)
        .fetch_one(pool)
        .await?;

    let olt = if let Some(olt_id) = router.mapped_olt_id {
        sqlx::query_as::<_, crate::models::Olt>("SELECT * FROM olts WHERE id = ?")
            .bind(olt_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let pool_rows = sqlx::query_as::<_, IpPoolRecord>(
        "SELECT * FROM ip_pools WHERE router_id = ? ORDER BY pool_name ASC",
    )
    .bind(router_id)
    .fetch_all(pool)
    .await?;

    Ok(ExplorerRow {
        router_id: router.id,
        device_name: router.name,
        wireguard_ip: router.wireguard_ip,
        auth_source: router.auth_source.clone(),
        olt_id: router.mapped_olt_id,
        mapped_by: Some(router.mapping_source.unwrap_or_else(|| "unmapped".to_string())),
        olt_name: olt.as_ref().map(|item| item.name.clone()),
        olt_ip: olt.as_ref().map(|item| item.ip_address.clone()),
        ip_pools: pool_rows
            .into_iter()
            .map(|pool| format!("{} ({})", pool.pool_name, pool.raw_ranges))
            .collect(),
        connection_status: router.connection_status,
        last_scanned_at: router.last_scanned_at,
        last_error: router.last_error,
        is_online: router.is_online,
        last_ping_at: router.last_ping_at,
    })
}

async fn mark_router_error(pool: &SqlitePool, router_id: i64, error_message: &str) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE routers
        SET connection_status = ?, mapping_source = ?, last_error = ?, last_scanned_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind("error")
    .bind("unmapped")
    .bind(error_message)
    .bind(now_rfc3339())
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn append_audit_log(
    pool: &SqlitePool,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: Option<String>,
    detail: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs (actor, action, target_type, target_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(detail)
    .bind(now_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

async fn load_default_mikrotik_credentials(
    pool: &SqlitePool,
    config: &AppConfig,
) -> AppResult<(Option<String>, Option<String>, String)> {
    let db_username = load_setting(pool, "mikrotik.default_username").await?;
    let db_password_encrypted = load_setting(pool, "mikrotik.default_password").await?;
    let db_password = match db_password_encrypted {
        Some(value) => Some(crypto::decrypt(&config.crypto_key, &value)?),
        None => None,
    };

    if db_username.is_some() && db_password.is_some() {
        return Ok((db_username, db_password, "database".to_string()));
    }

    if config.mikrotik_username.is_some() && config.mikrotik_password.is_some() {
        return Ok((
            config.mikrotik_username.clone(),
            config.mikrotik_password.clone(),
            "env".to_string(),
        ));
    }

    if db_username.is_some() || db_password.is_some() {
        return Ok((db_username, db_password, "database_partial".to_string()));
    }

    if config.mikrotik_username.is_some() || config.mikrotik_password.is_some() {
        return Ok((
            config.mikrotik_username.clone(),
            config.mikrotik_password.clone(),
            "env_partial".to_string(),
        ));
    }

    Ok((None, None, "none".to_string()))
}

async fn load_setting(pool: &SqlitePool, key: &str) -> AppResult<Option<String>> {
    let row: Option<(Option<String>,)> = sqlx::query_as("SELECT value FROM app_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|(value,)| value))
}

async fn upsert_setting(pool: &SqlitePool, key: &str, value: Option<&str>) -> AppResult<()> {
    match value {
        Some(value) => {
            sqlx::query(
                r#"
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(key)
            .bind(value)
            .bind(now_rfc3339())
            .execute(pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM app_settings WHERE key = ?")
                .bind(key)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

fn csv_escape(input: &str) -> String {
    let escaped = input.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

// --- WireGuard replace functions ---

pub(crate) async fn replace_wireguard_interfaces(
    pool: &SqlitePool,
    router_id: i64,
    interfaces: &[WireguardApiInterface],
) -> AppResult<()> {
    sqlx::query("DELETE FROM wireguard_interfaces WHERE router_id = ?")
        .bind(router_id)
        .execute(pool)
        .await?;

    for iface in interfaces {
        let running: bool = iface.running.as_deref() == Some("true");
        let disabled: bool = iface.disabled.as_deref() == Some("true");
        sqlx::query(
            r#"
            INSERT INTO wireguard_interfaces (router_id, name, listen_port, public_key, mtu, running, disabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(router_id)
        .bind(&iface.name)
        .bind(&iface.listen_port)
        .bind(&iface.public_key)
        .bind(&iface.mtu)
        .bind(running)
        .bind(disabled)
        .bind(now_rfc3339())
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub(crate) async fn replace_wireguard_peers(
    pool: &SqlitePool,
    router_id: i64,
    peers: &[WireguardApiPeer],
) -> AppResult<()> {
    sqlx::query("DELETE FROM wireguard_peers WHERE router_id = ?")
        .bind(router_id)
        .execute(pool)
        .await?;

    for peer in peers {
        sqlx::query(
            r#"
            INSERT INTO wireguard_peers (router_id, interface_name, public_key, endpoint_address, endpoint_port, allowed_address, current_endpoint_address, current_endpoint_port, last_handshake, rx, tx, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(router_id)
        .bind(&peer.interface)
        .bind(&peer.public_key)
        .bind(&peer.endpoint_address)
        .bind(&peer.endpoint_port)
        .bind(&peer.allowed_address)
        .bind(&peer.current_endpoint_address)
        .bind(&peer.current_endpoint_port)
        .bind(&peer.last_handshake)
        .bind(&peer.rx)
        .bind(&peer.tx)
        .bind(now_rfc3339())
        .bind(now_rfc3339())
        .execute(pool)
        .await?;
    }

    Ok(())
}

// --- WireGuard endpoint ---

async fn get_router_wireguard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(router_id): Path<i64>,
) -> AppResult<Json<WireguardDataResponse>> {
    let _actor = require_auth(&state, &headers)?;

    // Verify router exists
    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM routers WHERE id = ?")
        .bind(router_id)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::NotFound(format!("router {router_id} not found")));
    }

    let interfaces = sqlx::query_as::<_, WireguardInterfaceRecord>(
        "SELECT * FROM wireguard_interfaces WHERE router_id = ? ORDER BY name ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;

    let peers = sqlx::query_as::<_, WireguardPeerRecord>(
        "SELECT * FROM wireguard_peers WHERE router_id = ? ORDER BY interface_name ASC, id ASC",
    )
    .bind(router_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(WireguardDataResponse { interfaces, peers }))
}

// --- Subnet CRUD ---

async fn list_subnets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SubnetDefinitionRecord>>> {
    let _actor = require_auth(&state, &headers)?;
    let rows = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions ORDER BY cidr ASC",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn create_subnet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSubnetRequest>,
) -> AppResult<(StatusCode, Json<SubnetDefinitionRecord>)> {
    let _actor = require_auth(&state, &headers)?;

    let net = validate_cidr(&payload.cidr)
        .map_err(|e| AppError::BadRequest(e))?;
    let cidr = net.to_string();

    // Check for duplicate
    let existing: Option<(i64,)> = sqlx::query_as("SELECT id FROM subnet_definitions WHERE cidr = ?")
        .bind(&cidr)
        .fetch_optional(&state.pool)
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict(format!("subnet {cidr} already exists")));
    }

    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO subnet_definitions (cidr, label, created_at, updated_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&cidr)
    .bind(&payload.label)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    let record = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions WHERE cidr = ?",
    )
    .bind(&cidr)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(record)))
}

async fn update_subnet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(subnet_id): Path<i64>,
    Json(payload): Json<UpdateSubnetRequest>,
) -> AppResult<Json<SubnetDefinitionRecord>> {
    let _actor = require_auth(&state, &headers)?;

    let existing = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions WHERE id = ?",
    )
    .bind(subnet_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(existing) = existing else {
        return Err(AppError::NotFound(format!("subnet {subnet_id} not found")));
    };

    let new_cidr = if let Some(ref cidr_input) = payload.cidr {
        let net = validate_cidr(cidr_input)
            .map_err(|e| AppError::BadRequest(e))?;
        let cidr = net.to_string();
        // Check for duplicate if CIDR changed
        if cidr != existing.cidr {
            let dup: Option<(i64,)> = sqlx::query_as("SELECT id FROM subnet_definitions WHERE cidr = ? AND id != ?")
                .bind(&cidr)
                .bind(subnet_id)
                .fetch_optional(&state.pool)
                .await?;
            if dup.is_some() {
                return Err(AppError::Conflict(format!("subnet {cidr} already exists")));
            }
        }
        cidr
    } else {
        existing.cidr.clone()
    };

    let new_label = payload.label.unwrap_or(existing.label);

    sqlx::query("UPDATE subnet_definitions SET cidr = ?, label = ?, updated_at = ? WHERE id = ?")
        .bind(&new_cidr)
        .bind(&new_label)
        .bind(now_rfc3339())
        .bind(subnet_id)
        .execute(&state.pool)
        .await?;

    let record = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions WHERE id = ?",
    )
    .bind(subnet_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(record))
}

async fn delete_subnet(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(subnet_id): Path<i64>,
) -> AppResult<StatusCode> {
    let _actor = require_auth(&state, &headers)?;

    let result = sqlx::query("DELETE FROM subnet_definitions WHERE id = ?")
        .bind(subnet_id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("subnet {subnet_id} not found")));
    }

    Ok(StatusCode::NO_CONTENT)
}

// --- Utilization and suggestions endpoints ---

async fn get_subnet_utilization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<SubnetUtilizationResponse>> {
    let _actor = require_auth(&state, &headers)?;
    let subnets = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions ORDER BY cidr ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    let utilization = utilization::compute_utilization(&state.pool, &subnets).await?;
    Ok(Json(SubnetUtilizationResponse { subnets: utilization }))
}

async fn get_subnet_suggestions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SubnetSuggestion>>> {
    let _actor = require_auth(&state, &headers)?;
    let existing = sqlx::query_as::<_, SubnetDefinitionRecord>(
        "SELECT * FROM subnet_definitions ORDER BY cidr ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    let suggestions = utilization::compute_suggestions(&state.pool, &existing).await?;
    Ok(Json(suggestions))
}

fn issue_session_token(config: &AppConfig, username: &str, expires_at: DateTime<Utc>) -> AppResult<String> {
    let secret = config.session_token.as_deref().ok_or(AppError::Unauthorized)?;
    let issued_at = Utc::now().timestamp_millis();
    let payload = format!("{username}|{}|{issued_at}", expires_at.timestamp());
    let signature = sign_token(secret, &payload)?;
    Ok(format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn validate_session_token(config: &AppConfig, token: &str) -> AppResult<String> {
    let secret = config.session_token.as_deref().ok_or(AppError::Unauthorized)?;
    let (payload_b64, signature_b64) = token.split_once('.').ok_or(AppError::Unauthorized)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::Unauthorized)?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| AppError::Unauthorized)?;
    let payload = String::from_utf8(payload_bytes).map_err(|_| AppError::Unauthorized)?;

    verify_token_signature(secret, &payload, &signature)?;

    let mut parts = payload.split('|');
    let username = parts.next().ok_or(AppError::Unauthorized)?;
    let expires_at = parts
        .next()
        .ok_or(AppError::Unauthorized)?
        .parse::<i64>()
        .map_err(|_| AppError::Unauthorized)?;
    let _issued_at = parts.next().ok_or(AppError::Unauthorized)?;

    if Utc::now().timestamp() > expires_at {
        return Err(AppError::Unauthorized);
    }

    Ok(username.to_string())
}

fn sign_token(secret: &str, payload: &str) -> AppResult<Vec<u8>> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| AppError::Internal(err.to_string()))?;
    mac.update(payload.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_token_signature(secret: &str, payload: &str, signature: &[u8]) -> AppResult<()> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| AppError::Internal(err.to_string()))?;
    mac.update(payload.as_bytes());
    mac.verify_slice(signature).map_err(|_| AppError::Unauthorized)
}
