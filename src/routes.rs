use std::net::IpAddr;

use axum::{
    extract::{Multipart, State},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use sqlx::SqlitePool;

use crate::{
    app_error::{AppError, AppResult},
    mikrotik::MikrotikClient,
    models::{
        now_rfc3339, BookmarkOlt, ExplorerRow, ImportBookmarksResponse, RouterApiRoute, ScanRouterRequest,
        ScanRouterResponse,
    },
    net::{parse_scope, ranges_to_scopes},
    parser::parse_bookmarks_html,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub mikrotik: MikrotikClient,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/bookmarks/import", post(import_bookmarks))
        .route("/api/routers/scan", post(scan_router))
        .route("/api/explorer", get(list_explorer))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
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
    let wireguard_ip = payload.wireguard_ip.trim();
    if wireguard_ip.is_empty() {
        return Err(AppError::BadRequest("wireguard_ip is required".to_string()));
    }

    let device_name = payload
        .device_name
        .unwrap_or_else(|| format!("Router-{wireguard_ip}"));
    let router_id = upsert_router(&state.pool, &device_name, wireguard_ip).await?;

    let pools = match state.mikrotik.fetch_pools(wireguard_ip).await {
        Ok(pools) => pools,
        Err(err) => {
            mark_router_error(&state.pool, router_id, &err.to_string()).await?;
            return Err(err);
        }
    };

    let routes = match state.mikrotik.fetch_routes(wireguard_ip).await {
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
        SET connection_status = ?, mapped_olt_id = ?, last_error = NULL, last_scanned_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind("connected")
    .bind(mapping.as_ref().map(|(id, _, _)| *id))
    .bind(now_rfc3339())
    .bind(now_rfc3339())
    .bind(router_id)
    .execute(&state.pool)
    .await?;

    let explorer_row = fetch_explorer_row(&state.pool, router_id).await?;
    let matched_by = mapping.map(|(_, _, reason)| reason);

    Ok(Json(ScanRouterResponse {
        router: explorer_row,
        matched_by,
    }))
}

async fn list_explorer(State(state): State<AppState>) -> AppResult<Json<Vec<ExplorerRow>>> {
    let rows = sqlx::query_as::<_, crate::models::RouterRecord>(
        "SELECT * FROM routers ORDER BY updated_at DESC, id DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(fetch_explorer_row(&state.pool, row.id).await?);
    }

    Ok(Json(items))
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

async fn upsert_router(pool: &SqlitePool, device_name: &str, wireguard_ip: &str) -> AppResult<i64> {
    let api_base_url = format!("https://{wireguard_ip}/rest");
    sqlx::query(
        r#"
        INSERT INTO routers (name, wireguard_ip, api_base_url, connection_status, updated_at)
        VALUES (?, ?, ?, 'connecting', ?)
        ON CONFLICT(wireguard_ip) DO UPDATE SET
            name = excluded.name,
            api_base_url = excluded.api_base_url,
            connection_status = excluded.connection_status,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(device_name)
    .bind(wireguard_ip)
    .bind(api_base_url)
    .bind(now_rfc3339())
    .execute(pool)
    .await?;

    let row: (i64,) = sqlx::query_as("SELECT id FROM routers WHERE wireguard_ip = ?")
        .bind(wireguard_ip)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

async fn replace_ip_pools(
    pool: &SqlitePool,
    router_id: i64,
    pools: &[crate::models::RouterApiPool],
) -> AppResult<()> {
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
    pools: &[crate::models::RouterApiPool],
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
    let router = sqlx::query_as::<_, crate::models::RouterRecord>("SELECT * FROM routers WHERE id = ?")
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
