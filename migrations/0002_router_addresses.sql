CREATE TABLE IF NOT EXISTS router_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    interface TEXT NOT NULL,
    network TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_router_addresses_router_id ON router_addresses(router_id);
