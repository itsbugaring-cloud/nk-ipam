use std::time::Duration;

use sqlx::SqlitePool;
use tokio::net::TcpStream;
use tokio::time;

use crate::crypto;
use crate::routes::AppState;

pub fn start_workers(state: AppState) {
    let ping_state = state.clone();
    tokio::spawn(async move {
        ping_worker_loop(ping_state).await;
    });

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_worker_loop(cleanup_state).await;
    });

    let sync_state = state.clone();
    tokio::spawn(async move {
        sync_worker_loop(sync_state).await;
    });
}

async fn ping_worker_loop(state: AppState) {
    let interval_secs = 60; // Ping every minute for better real-time feel
    let mut interval = time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        
        let routers = match sqlx::query!("SELECT id, wireguard_ip FROM routers").fetch_all(&state.pool).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("Failed to fetch routers for ping: {}", e);
                continue;
            }
        };

        for router in routers {
            let is_online = check_tcp_port(&router.wireguard_ip, 80).await;
            
            let now = chrono::Utc::now().to_rfc3339();
            let res = sqlx::query!(
                "UPDATE routers SET is_online = ?, last_ping_at = ? WHERE id = ?",
                is_online, now, router.id
            )
            .execute(&state.pool)
            .await;

            if let Err(e) = res {
                tracing::error!("Failed to update ping status for router {}: {}", router.id, e);
            }
        }
    }
}

async fn check_tcp_port(ip: &str, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    match time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn cleanup_worker_loop(state: AppState) {
    let interval_secs = 86400; // 24 hours
    let mut interval = time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        tracing::debug!("Running audit log cleanup worker...");
        
        let thirty_days_ago = chrono::Utc::now() - chrono::Duration::days(30);
        let timestamp = thirty_days_ago.to_rfc3339();

        let res = sqlx::query!("DELETE FROM audit_logs WHERE created_at < ?", timestamp)
            .execute(&state.pool)
            .await;

        match res {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    tracing::info!("Cleaned up {} old audit logs", result.rows_affected());
                }
            }
            Err(e) => tracing::error!("Failed to clean up audit logs: {}", e),
        }
    }
}

async fn sync_worker_loop(state: AppState) {
    let interval_secs = 3600; // 1 hour
    let mut interval = time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        tracing::debug!("Running auto-sync worker...");
        
        // Fetch routers that are mapped and online
        let routers = match sqlx::query!(
            "SELECT id, wireguard_ip, auth_username, auth_password FROM routers WHERE mapped_olt_id IS NOT NULL AND is_online = true"
        )
        .fetch_all(&state.pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("Failed to fetch routers for auto-sync: {}", e);
                continue;
            }
        };

        for router in routers {
            let username = router.auth_username.unwrap_or_else(|| "admin".to_string());
            let password = router.auth_password
                .and_then(|enc| crypto::decrypt(&state.config.crypto_key, &enc).ok())
                .unwrap_or_default();

            // Fetch addresses
            if let Ok(addresses) = state.mikrotik.fetch_addresses(&router.wireguard_ip, &username, &password).await {
                let _ = crate::routes::replace_router_addresses(&state.pool, router.id, &addresses).await;
            }

            // Fetch pools
            if let Ok(pools) = state.mikrotik.fetch_pools(&router.wireguard_ip, &username, &password).await {
                let _ = crate::routes::replace_ip_pools(&state.pool, router.id, &pools).await;
            }

            // Fetch routes
            if let Ok(routes) = state.mikrotik.fetch_routes(&router.wireguard_ip, &username, &password).await {
                let _ = crate::routes::replace_router_routes(&state.pool, router.id, &routes).await;
            }

            // Fetch wireguard
            if let Ok(wg_ifaces) = state.mikrotik.fetch_wireguard_interfaces(&router.wireguard_ip, &username, &password).await {
                let _ = crate::routes::replace_wireguard_interfaces(&state.pool, router.id, &wg_ifaces).await;
            }
            if let Ok(wg_peers) = state.mikrotik.fetch_wireguard_peers(&router.wireguard_ip, &username, &password).await {
                let _ = crate::routes::replace_wireguard_peers(&state.pool, router.id, &wg_peers).await;
            }

            // Update last_scanned_at
            let now = chrono::Utc::now().to_rfc3339();
            let _ = sqlx::query!(
                "UPDATE routers SET last_scanned_at = ?, updated_at = ? WHERE id = ?",
                now, now, router.id
            ).execute(&state.pool).await;
        }
    }
}
