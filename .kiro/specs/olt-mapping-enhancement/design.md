# Implementation Plan

## Overview

This design corrects the OLT auto-mapping logic by introducing `/rest/ip/address` as the primary data source for matching OLT IPs to routers. The existing route and pool matching is demoted to fallback status. A new database table stores fetched interface addresses, and the UI is updated to display them.

## Architecture

### Data Flow

```
Router Scan Request
    │
    ▼
┌─────────────────────────────┐
│  MikroTik_Client            │
│  1. GET /rest/ip/address    │
│  2. GET /rest/ip/pool       │
│  3. GET /rest/ip/route      │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│  Mapping_Engine             │
│  Priority:                  │
│  1. auto_address (interface)│
│  2. auto_route (routes)     │
│  3. auto_pool (pools)       │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│  Database                   │
│  - router_addresses (new)   │
│  - ip_pools (existing)      │
│  - router_routes (existing) │
└─────────────────────────────┘
```

### Components Modified

1. **`src/mikrotik.rs`** — Add `fetch_addresses()` method and `RouterApiAddress` model
2. **`src/models.rs`** — Add `RouterApiAddress` struct and `RouterAddressRecord` DB model
3. **`src/routes.rs`** — Update `scan_router_payload()` and rewrite `find_matching_olt()` with new priority logic
4. **`src/net.rs`** — Add `extract_host_ip()` helper to strip CIDR prefix
5. **`migrations/`** — New migration for `router_addresses` table
6. **`static/index.html`** — Display interface addresses in router detail view

## Database Changes

### New Table: `router_addresses`

```sql
CREATE TABLE IF NOT EXISTS router_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    address TEXT NOT NULL,       -- Full CIDR notation e.g. "192.168.5.254/24"
    interface TEXT NOT NULL,     -- Interface name e.g. "ether1"
    network TEXT,               -- Network address e.g. "192.168.5.0"
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_router_addresses_router_id ON router_addresses(router_id);
```

## Detailed Design

### 1. MikroTik Client: `fetch_addresses()`

Add to `src/mikrotik.rs`:

```rust
// New model in src/models.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterApiAddress {
    pub address: String,           // e.g. "192.168.5.254/24"
    pub interface: String,         // e.g. "ether1"
    pub network: Option<String>,   // e.g. "192.168.5.0"
}

// New method in MikrotikClient
pub async fn fetch_addresses(
    &self,
    wireguard_ip: &str,
    username: &str,
    password: &str,
) -> AppResult<Vec<RouterApiAddress>> {
    let scheme = self.scheme();
    self.get_json(
        &format!("{scheme}://{wireguard_ip}/rest/ip/address"),
        username,
        password,
    )
    .await
}
```

### 2. IP Parsing: `extract_host_ip()`

Add to `src/net.rs`:

```rust
/// Extracts the host IP from a CIDR string like "192.168.5.254/24" → "192.168.5.254"
/// If no prefix is present, returns the input parsed as an IP address.
pub fn extract_host_ip(address: &str) -> Option<IpAddr> {
    let trimmed = address.trim();
    if let Some((ip_part, _prefix)) = trimmed.split_once('/') {
        ip_part.parse::<IpAddr>().ok()
    } else {
        trimmed.parse::<IpAddr>().ok()
    }
}
```

### 3. Updated `find_matching_olt()`

The function signature changes to accept the new addresses parameter:

```rust
async fn find_matching_olt(
    pool: &SqlitePool,
    addresses: &[RouterApiAddress],
    pools: &[RouterApiPool],
    routes: &[RouterApiRoute],
) -> AppResult<Option<(i64, String, String)>> {
    let olts = sqlx::query_as::<_, Olt>("SELECT * FROM olts")
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

    for olt in &olts {
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
```

### 4. Scan Flow Update

In `scan_router_payload()`, add the address fetch before pools/routes:

```rust
// Fetch addresses (new - highest priority data source)
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

// Store addresses in DB (replace existing)
replace_router_addresses(&state.pool, router_id, &addresses).await?;

// ... existing pool and route fetching ...

// Updated mapping call with addresses
let mapping = find_matching_olt(&state.pool, &addresses, &pools, &routes).await?;
```

### 5. Database Helper: `replace_router_addresses()`

```rust
async fn replace_router_addresses(
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
            "INSERT INTO router_addresses (router_id, address, interface, network, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
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
```

### 6. Router Detail API Update

Add `addresses` field to `RouterDetailResponse`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct RouterDetailResponse {
    pub router: ExplorerRow,
    pub pools: Vec<IpPoolRecord>,
    pub routes: Vec<RouterRouteRecord>,
    pub addresses: Vec<RouterAddressRecord>,  // NEW
}
```

### 7. Frontend Changes

In the router detail modal/view, add a section displaying interface addresses in a table with columns: Interface, Address, Network.

## Correctness Properties

### Property 1: IP Extraction Round-Trip

For any valid IPv4 or IPv6 address `ip` and any valid prefix length `prefix`, `extract_host_ip("{ip}/{prefix}")` returns `Some(ip)`.

**Covers:** Requirement 2, Criteria 2.1, 2.2

### Property 2: Address Match Priority Dominance

For any set of OLTs, interface addresses, routes, and pools where an OLT IP appears in both the interface addresses and a route/pool scope, the Mapping_Engine always returns `auto_address` as the mapping source.

**Covers:** Requirement 3, Criteria 3.3, 3.4; Requirement 4, Criteria 4.3

### Property 3: Mapping Completeness

For any OLT IP that exactly equals a host IP in the interface addresses list, `find_matching_olt` returns `Some(...)` with source `auto_address`. For any OLT IP not present in any of the three data sources, `find_matching_olt` returns `None`.

**Covers:** Requirement 3, Criteria 3.1, 3.2

### Property 4: Fallback Ordering

For any input where no address match exists but a route match does, the result is `auto_route`. For any input where no address or route match exists but a pool match does, the result is `auto_pool`.

**Covers:** Requirement 4, Criteria 4.1, 4.2, 4.3

### Property 5: Replace Semantics (Idempotence)

Calling `replace_router_addresses` twice with the same data produces the same stored state as calling it once. Calling it with new data fully replaces the previous set.

**Covers:** Requirement 5, Criteria 5.2

## Testing Strategy

| Property | Type | Approach |
|----------|------|----------|
| IP Extraction Round-Trip | Property-based | Generate random valid IPs + prefixes, verify extraction |
| Address Match Priority | Property-based | Generate OLTs + addresses + routes + pools with overlaps |
| Mapping Completeness | Property-based | Generate sets where OLT is/isn't in addresses |
| Fallback Ordering | Property-based | Generate sets with controlled match locations |
| Replace Semantics | Integration | Test with SQLite in-memory DB |
| API endpoint calls | Integration | Mock HTTP server returning known JSON |
| UI display | Manual | Verify interface addresses table renders correctly |

## File Changes Summary

| File | Change |
|------|--------|
| `migrations/0002_router_addresses.sql` | New migration: `router_addresses` table |
| `src/models.rs` | Add `RouterApiAddress`, `RouterAddressRecord` structs |
| `src/mikrotik.rs` | Add `fetch_addresses()` method |
| `src/net.rs` | Add `extract_host_ip()` function |
| `src/routes.rs` | Update `find_matching_olt()`, `scan_router_payload()`, `get_router_detail()`, add `replace_router_addresses()` |
| `static/index.html` | Add interface addresses display in router detail view |
