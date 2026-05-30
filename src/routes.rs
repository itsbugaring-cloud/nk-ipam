use std::net::IpAddr;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{stream, StreamExt};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::{
    app_error::{AppError, AppResult},
    config::AppConfig,
    mikrotik::MikrotikClient,
    models::{
        now_rfc3339, BookmarkOlt, BulkScanItemResult, BulkScanRequest, BulkScanResponse, ExplorerRow,
        HealthResponse, ImportBookmarksResponse, OltOption, RouterApiPool, RouterApiRoute, RouterRecord,
        ScanRouterRequest, ScanRouterResponse, UpdateRouterMappingRequest,
    },
    net::{parse_scope, ranges_to_scopes},
    parser::parse_bookmarks_html,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub mikrotik: MikrotikClient,
    pub config: AppConfig,
}

#[derive(Debug, Deserialize)]
struct ExplorerQuery {
    q: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/bookmarks/import", post(import_bookmarks))
        .route("/api/routers/scan", post(scan_router))
        .route("/api/routers/bulk-scan", post(bulk_scan_routers))
        .route("/api/routers/:id/rescan", post(rescan_router))
        .route("/api/routers/:id/map-olt", post(update_router_mapping))
        .route("/api/routers/export.csv", get(export_explorer_csv))
        .route("/api/olts", get(list_olts))
        .route("/api/explorer", get(list_explorer))
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

    Ok(Json(HealthResponse {
        status,
        database: database.to_string(),
        default_credentials: state.config.mikrotik_username.is_some()
            && state.config.mikrotik_password.is_some(),
    }))
}

async fn import_bookmarks(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> AppResult<Json<ImportBookmarksResponse>> {
    let mut imported = 0usize;

    while let Some(field) = multipart.next_field().await? {
        if field.name() != Some("file") {
            continue;
        }

        let content = field.text().await?;
        let records = parse_bookmarks_html(&content)?;
        imported += upsert_olts(&state.pool, &records).await?;
    }

    Ok(Json(ImportBookmarksResponse { imported }))
}

async fn scan_router(
    State(state): State<AppState>,
    Json(payload): Json<ScanRouterRequest>,
) -> AppResult<Json<ScanRouterResponse>> {
    let result = scan_router_payload(&state, payload).await?;
    Ok(Json(result))
}

async fn bulk_scan_routers(
    State(state): State<AppState>,
    Json(payload): Json<BulkScanRequest>,
) -> AppResult<Json<BulkScanResponse>> {
    if payload.routers.is_empty() {
        return Err(AppError::BadRequest(
            "routers collection must contain at least one item".to_string(),
        ));
    }

    let concurrency = state.config.max_scan_concurrency.max(1);
    let results = stream::iter(payload.routers.into_iter().map(|router| {
        let state = state.clone();
        async move {
            let wireguard_ip = router.wireguard_ip.clone();
            match scan_router_payload(&state, router).await {
                Ok(response) => BulkScanItemResult {
                    wireguard_ip,
                    success: true,
                    matched_by: response.matched_by,
                    router: Some(response.router),
                    error: None,
                },
                Err(err) => BulkScanItemResult {
                    wireguard_ip,
                    success: false,
                    matched_by: None,
                    router: None,
                    error: Some(err.to_string()),
                },
            }
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;

    let success_count = results.iter().filter(|item| item.success).count();
    let failure_count = results.len().saturating_sub(success_count);

    Ok(Json(BulkScanResponse {
        success_count,
        failure_count,
        results,
    }))
}

async fn list_explorer(
    State(state): State<AppState>,
    Query(query): Query<ExplorerQuery>,
) -> AppResult<Json<Vec<ExplorerRow>>> {
    let items = fetch_explorer_rows(&state.pool, query.q.as_deref()).await?;
    Ok(Json(items))
}

async fn export_explorer_csv(
    State(state): State<AppState>,
    Query(query): Query<ExplorerQuery>,
) -> AppResult<impl IntoResponse> {
    let rows = fetch_explorer_rows(&state.pool, query.q.as_deref()).await?;

    let mut csv = String::from(
        "device_name,wireguard_ip,auth_source,mapped_by,olt_name,olt_ip,ip_pools,connection_status,last_scanned_at,last_error\n",
    );

    for row in rows {
        let record = [
            csv_escape(&row.device_name),
            csv_escape(&row.wireguard_ip),
            csv_escape(&row.auth_source),
            csv_escape(row.mapped_by.as_deref().unwrap_or("-")),
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

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"netking-ipam-explorer.csv\""),
    );

    Ok((StatusCode::OK, headers, csv))
}

async fn list_olts(State(state): State<AppState>) -> AppResult<Json<Vec<OltOption>>> {
    let olts = sqlx::query_as::<_, crate::models::Olt>("SELECT * FROM olts ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(
        olts.into_iter()
            .map(|olt| OltOption {
                id: olt.id,
                name: olt.name,
                ip_address: olt.ip_address,
            })
            .collect(),
    ))
}

async fn update_router_mapping(
    State(state): State<AppState>,
    Path(router_id): Path<i64>,
    Json(payload): Json<UpdateRouterMappingRequest>,
) -> AppResult<Json<ExplorerRow>> {
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
    .bind(payload.olt_id.map(|_| "manual".to_string()))
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(&state.pool)
    .await?;

    let row = fetch_explorer_row(&state.pool, router_id).await?;
    Ok(Json(row))
}

async fn rescan_router(
    State(state): State<AppState>,
    Path(router_id): Path<i64>,
) -> AppResult<Json<ScanRouterResponse>> {
    let router = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers WHERE id = ?")
        .bind(router_id)
        .fetch_one(&state.pool)
        .await?;

    let payload = ScanRouterRequest {
        wireguard_ip: router.wireguard_ip,
        device_name: Some(router.name),
        username: router.auth_username,
        password: router.auth_password,
    };

    let response = scan_router_payload(&state, payload).await?;
    Ok(Json(response))
}

async fn scan_router_payload(state: &AppState, payload: ScanRouterRequest) -> AppResult<ScanRouterResponse> {
    let wireguard_ip = payload.wireguard_ip.trim().to_string();
    if wireguard_ip.is_empty() {
        return Err(AppError::BadRequest("wireguard_ip is required".to_string()));
    }

    let device_name = payload
        .device_name
        .clone()
        .unwrap_or_else(|| format!("Router-{wireguard_ip}"));
    let credentials = resolve_credentials(state, &payload)?;
    let auth_source = if payload.username.as_deref().is_some() && payload.password.as_deref().is_some() {
        "router"
    } else {
        "env"
    };

    let router_id = upsert_router(
        &state.pool,
        &device_name,
        &wireguard_ip,
        payload.username.as_deref(),
        payload.password.as_deref(),
        auth_source,
    )
    .await?;

    let pools = match state
        .mikrotik
        .fetch_pools(&wireguard_ip, &credentials.0, &credentials.1)
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
        .fetch_routes(&wireguard_ip, &credentials.0, &credentials.1)
        .await
    {
        Ok(routes) => routes,
        Err(err) => {
            mark_router_error(&state.pool, router_id, &err.to_string()).await?;
            return Err(err);
        }
    };

    replace_ip_pools(&state.pool, router_id, &pools).await?;
    let mapping = find_matching_olt(&state.pool, &pools, &routes).await?;

    sqlx::query(
        r#"
        UPDATE routers
        SET connection_status = ?, mapped_olt_id = ?, mapping_source = ?, last_error = NULL, last_scanned_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind("connected")
    .bind(mapping.as_ref().map(|(id, _, _)| *id))
    .bind(mapping.as_ref().map(|(_, _, reason)| reason.clone()))
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
    })
}

fn resolve_credentials(state: &AppState, payload: &ScanRouterRequest) -> AppResult<(String, String)> {
    let username = payload
        .username
        .clone()
        .or_else(|| state.config.mikrotik_username.clone())
        .ok_or_else(|| AppError::BadRequest("username is required either in request or env".to_string()))?;
    let password = payload
        .password
        .clone()
        .or_else(|| state.config.mikrotik_password.clone())
        .ok_or_else(|| AppError::BadRequest("password is required either in request or env".to_string()))?;

    Ok((username, password))
}

async fn fetch_explorer_rows(pool: &SqlitePool, keyword: Option<&str>) -> AppResult<Vec<ExplorerRow>> {
    let rows = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers ORDER BY updated_at DESC, id DESC")
        .fetch_all(pool)
        .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(fetch_explorer_row(pool, row.id).await?);
    }

    if let Some(keyword) = keyword {
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

    Ok(items)
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
    device_name: &str,
    wireguard_ip: &str,
    auth_username: Option<&str>,
    auth_password: Option<&str>,
    auth_source: &str,
) -> AppResult<i64> {
    let api_base_url = format!("https://{wireguard_ip}/rest");
    sqlx::query(
        r#"
        INSERT INTO routers (
            name, wireguard_ip, api_base_url, auth_username, auth_password, auth_source, connection_status, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'connecting', ?)
        ON CONFLICT(wireguard_ip) DO UPDATE SET
            name = excluded.name,
            api_base_url = excluded.api_base_url,
            auth_username = COALESCE(excluded.auth_username, routers.auth_username),
            auth_password = COALESCE(excluded.auth_password, routers.auth_password),
            auth_source = excluded.auth_source,
            connection_status = excluded.connection_status,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(device_name)
    .bind(wireguard_ip)
    .bind(api_base_url)
    .bind(auth_username)
    .bind(auth_password)
    .bind(auth_source)
    .bind(now_rfc3339())
    .execute(pool)
    .await?;

    let row: (i64,) = sqlx::query_as("SELECT id FROM routers WHERE wireguard_ip = ?")
        .bind(wireguard_ip)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

async fn replace_ip_pools(pool: &SqlitePool, router_id: i64, pools: &[RouterApiPool]) -> AppResult<()> {
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

async fn find_matching_olt(
    pool: &SqlitePool,
    pools: &[RouterApiPool],
    routes: &[RouterApiRoute],
) -> AppResult<Option<(i64, String, String)>> {
    let olts = sqlx::query_as::<_, crate::models::Olt>("SELECT * FROM olts")
        .fetch_all(pool)
        .await?;

    let route_scopes: Vec<_> = routes
        .iter()
        .filter_map(|route| route.dst_address.as_deref())
        .filter_map(parse_scope)
        .collect();

    let pool_scopes: Vec<_> = pools
        .iter()
        .flat_map(|item| ranges_to_scopes(&item.ranges))
        .collect();

    for olt in olts {
        let ip = match olt.ip_address.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        if route_scopes.iter().any(|scope| scope.contains_ip(ip)) {
            return Ok(Some((olt.id, olt.ip_address.clone(), "route.dst-address".to_string())));
        }

        if pool_scopes.iter().any(|scope| scope.contains_ip(ip)) {
            return Ok(Some((olt.id, olt.ip_address.clone(), "ip.pool.ranges".to_string())));
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

    let pool_rows = sqlx::query_as::<_, crate::models::IpPoolRecord>(
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
        mapped_by: router.mapping_source.clone(),
        olt_name: olt.as_ref().map(|item| item.name.clone()),
        olt_ip: olt.as_ref().map(|item| item.ip_address.clone()),
        ip_pools: pool_rows
            .into_iter()
            .map(|pool| format!("{} ({})", pool.pool_name, pool.raw_ranges))
            .collect(),
        connection_status: router.connection_status,
        last_scanned_at: router.last_scanned_at,
        last_error: router.last_error,
    })
}

async fn mark_router_error(pool: &SqlitePool, router_id: i64, error_message: &str) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE routers
        SET connection_status = ?, last_error = ?, last_scanned_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind("error")
    .bind(error_message)
    .bind(now_rfc3339())
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(pool)
    .await?;

    Ok(())
}

fn csv_escape(input: &str) -> String {
    let escaped = input.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
