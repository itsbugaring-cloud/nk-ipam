mod app_error;
mod config;
mod crypto;
mod db;
mod mikrotik;
mod models;
mod net;
mod parser;
mod routes;

use std::path::Path;

use axum::Router;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{app_error::AppResult, config::AppConfig, mikrotik::MikrotikClient, routes::AppState};

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = AppConfig::from_env()?;
    ensure_sqlite_parent_dir(&config.database_url)?;
    let pool = db::init_pool(&config.database_url).await?;
    let mikrotik = MikrotikClient::new(&config)?;

    let api_router = routes::build_router(AppState {
        pool,
        mikrotik,
        config: config.clone(),
    });
    let app = Router::new()
        .merge(api_router)
        .nest_service("/", ServeDir::new("static").append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!("Netking IPAM listening on http://{}", config.bind_addr);
    axum::serve(listener, app).await.map_err(|err| {
        crate::app_error::AppError::Internal(format!("server exited unexpectedly: {err}"))
    })
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netking_ipam=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn ensure_sqlite_parent_dir(database_url: &str) -> AppResult<()> {
    if let Some(path) = database_url.strip_prefix("sqlite://") {
        let db_path = Path::new(path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}
