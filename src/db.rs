use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

use crate::app_error::AppResult;

pub async fn init_pool(database_url: &str) -> AppResult<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

