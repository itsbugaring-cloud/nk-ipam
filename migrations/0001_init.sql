CREATE TABLE IF NOT EXISTS olts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    source_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    wireguard_ip TEXT NOT NULL UNIQUE,
    api_base_url TEXT NOT NULL,
    auth_username TEXT,
    auth_password TEXT,
    auth_source TEXT NOT NULL DEFAULT 'env',
    connection_status TEXT NOT NULL DEFAULT 'unknown',
    mapped_olt_id INTEGER,
    mapping_source TEXT,
    last_error TEXT,
    last_scanned_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(mapped_olt_id) REFERENCES olts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS ip_pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    pool_name TEXT NOT NULL,
    raw_ranges TEXT NOT NULL,
    derived_network TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_routers_wireguard_ip ON routers(wireguard_ip);
CREATE INDEX IF NOT EXISTS idx_routers_mapped_olt_id ON routers(mapped_olt_id);
CREATE INDEX IF NOT EXISTS idx_ip_pools_router_id ON ip_pools(router_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
