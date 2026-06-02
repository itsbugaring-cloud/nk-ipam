-- WireGuard interfaces collected from MikroTik routers
CREATE TABLE IF NOT EXISTS wireguard_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    listen_port TEXT,
    public_key TEXT,
    mtu TEXT,
    running INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_wg_interfaces_router_id ON wireguard_interfaces(router_id);

-- WireGuard peers collected from MikroTik routers
CREATE TABLE IF NOT EXISTS wireguard_peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    interface_name TEXT,
    public_key TEXT,
    endpoint_address TEXT,
    endpoint_port TEXT,
    allowed_address TEXT,
    current_endpoint_address TEXT,
    current_endpoint_port TEXT,
    last_handshake TEXT,
    rx TEXT,
    tx TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_wg_peers_router_id ON wireguard_peers(router_id);
CREATE INDEX IF NOT EXISTS idx_wg_peers_allowed_address ON wireguard_peers(allowed_address);

-- User-defined subnet labels for IP utilization tracking
CREATE TABLE IF NOT EXISTS subnet_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_subnet_definitions_cidr ON subnet_definitions(cidr);
