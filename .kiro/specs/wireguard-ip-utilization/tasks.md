# Implementation Plan: WireGuard IP Utilization

## Overview

This plan implements WireGuard data collection from MikroTik routers and a subnet utilization dashboard. Tasks are ordered so each builds on the previous — starting with the database schema, then models, then backend logic, then API routes, and finally the frontend.

## Tasks

- [ ] 1. Database migration and model structs
  - [-] 1.1 Create migration `migrations/0003_wireguard_subnets.sql`
    - Add `wireguard_interfaces` table with columns: id, router_id, name, listen_port, public_key, mtu, running, disabled, created_at, updated_at
    - Add `wireguard_peers` table with columns: id, router_id, interface_name, public_key, endpoint_address, endpoint_port, allowed_address, current_endpoint_address, current_endpoint_port, last_handshake, rx, tx, created_at, updated_at
    - Add `subnet_definitions` table with columns: id, cidr (UNIQUE), label, created_at, updated_at
    - Add indexes: idx_wg_interfaces_router_id, idx_wg_peers_router_id, idx_wg_peers_allowed_address, idx_subnet_definitions_cidr
    - Foreign keys on router_id referencing routers(id) ON DELETE CASCADE
    - _Requirements: 1.4, 2.4, 5.1_

  - [~] 1.2 Add WireGuard and subnet model structs to `src/models.rs`
    - Add `WireguardApiInterface` (serde rename for hyphenated MikroTik fields: listen-port, public-key, private-key)
    - Add `WireguardApiPeer` (serde rename for: endpoint-address, endpoint-port, allowed-address, current-endpoint-address, current-endpoint-port, last-handshake)
    - Add `WireguardInterfaceRecord` and `WireguardPeerRecord` (FromRow, Serialize)
    - Add `SubnetDefinitionRecord` (FromRow, Serialize, Deserialize)
    - Add request types: `CreateSubnetRequest`, `UpdateSubnetRequest`
    - Add response types: `WireguardDataResponse`, `SubnetUtilizationResponse`, `SubnetUtilization`, `UsedIpEntry`, `IpSource`, `SubnetSuggestion`
    - Update `RouterDetailResponse` to include `wireguard_interfaces` and `wireguard_peers` fields
    - _Requirements: 1.2, 2.2, 4.2, 5.1, 6.4, 9.3_

- [ ] 2. MikroTik client methods
  - [~] 2.1 Add `fetch_wireguard_interfaces` to `src/mikrotik.rs`
    - GET request to `{api_base_url}/interface/wireguard` (follow existing fetch_addresses pattern)
    - Parse JSON array into `Vec<WireguardApiInterface>`
    - Return `AppResult<Vec<WireguardApiInterface>>`
    - _Requirements: 1.1, 1.2_

  - [~] 2.2 Add `fetch_wireguard_peers` to `src/mikrotik.rs`
    - GET request to `{api_base_url}/interface/wireguard/peers`
    - Parse JSON array into `Vec<WireguardApiPeer>`
    - Return `AppResult<Vec<WireguardApiPeer>>`
    - _Requirements: 2.1, 2.2_

- [ ] 3. Net module helpers
  - [~] 3.1 Add CIDR validation and subnet membership helpers to `src/net.rs`
    - Add `validate_cidr(input: &str) -> Result<IpNet, String>` — validates well-formed IPv4/IPv6 CIDR with correct host bits zeroed
    - Add `ip_in_subnet(ip: IpAddr, net: &IpNet) -> bool` — checks if IP is within subnet (excluding network and broadcast for IPv4)
    - Add `total_hosts(net: &IpNet) -> u64` — computes usable host count (2^host_bits - 2 for IPv4, 2^host_bits for IPv6)
    - Add `expand_range_in_subnet(start: Ipv4Addr, end: Ipv4Addr, net: &IpNet) -> Vec<IpAddr>` — expands IP range and filters to those within subnet, with upper bound to prevent memory issues
    - _Requirements: 5.4, 6.3, 6.6_

- [ ] 4. Utilization module
  - [~] 4.1 Create `src/utilization.rs` and register module in `src/main.rs`
    - Add `mod utilization;` to main.rs
    - Implement `compute_utilization(pool: &SqlitePool, subnets: &[SubnetDefinitionRecord]) -> AppResult<Vec<SubnetUtilization>>`
    - Aggregate used IPs from: router_addresses (extract host IP), ip_pools (expand ranges), wireguard_peers (parse allowed_address comma-separated list)
    - Deduplicate IPs, track all sources per IP
    - Exclude network and broadcast addresses from used_ips
    - Calculate total_hosts, used_count, available_count, utilization_pct
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [~] 4.2 Implement subnet suggestion logic in `src/utilization.rs`
    - Add `compute_suggestions(pool: &SqlitePool, existing: &[SubnetDefinitionRecord]) -> AppResult<Vec<SubnetSuggestion>>`
    - Extract CIDRs from: router_addresses.network, ip_pools.derived_network, router_routes.dst_address, wireguard_peers.allowed_address
    - Filter out CIDRs that already exist in subnet_definitions
    - Generate proposed labels from source (e.g., "From address on Router-X")
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [~] 5. Checkpoint
  - Ensure all code compiles, ask the user if questions arise.

- [ ] 6. Scan flow update — WireGuard integration with graceful degradation
  - [~] 6.1 Add `replace_wireguard_interfaces` and `replace_wireguard_peers` DB functions in `src/routes.rs`
    - Follow existing `replace_router_addresses` pattern: DELETE all for router_id, then INSERT each record
    - Map `WireguardApiInterface` fields to `wireguard_interfaces` table columns (convert running/disabled strings to integer 0/1)
    - Map `WireguardApiPeer` fields to `wireguard_peers` table columns
    - _Requirements: 1.4, 2.4_

  - [~] 6.2 Integrate WireGuard fetch into `scan_router_payload` in `src/routes.rs`
    - After `replace_router_routes`, add calls to `fetch_wireguard_interfaces` and `fetch_wireguard_peers`
    - Wrap each in match — on error, log warning with `tracing::warn!` and continue with empty Vec (graceful degradation)
    - Call `replace_wireguard_interfaces` and `replace_wireguard_peers` with results
    - _Requirements: 1.3, 2.3, 3.1, 3.2, 3.3, 3.4_

- [ ] 7. Subnet CRUD API routes
  - [~] 7.1 Add subnet CRUD handlers and routes to `src/routes.rs`
    - `list_subnets` — GET /api/subnets, return all SubnetDefinitionRecord ordered by cidr
    - `create_subnet` — POST /api/subnets, validate CIDR with `validate_cidr`, check for duplicate (409 Conflict), insert record
    - `update_subnet` — PUT /api/subnets/:id, validate CIDR if provided, update record (404 if not found)
    - `delete_subnet` — DELETE /api/subnets/:id, remove record (404 if not found)
    - Register routes in `build_router`
    - All endpoints require auth via `require_auth`
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

- [ ] 8. Utilization and suggestions API routes
  - [~] 8.1 Add utilization and suggestions endpoints to `src/routes.rs`
    - `get_subnet_utilization` — GET /api/subnets/utilization, load all subnet_definitions, call `compute_utilization`, return SubnetUtilizationResponse
    - `get_subnet_suggestions` — GET /api/subnets/suggestions, load existing subnets, call `compute_suggestions`, return Vec<SubnetSuggestion>
    - Register routes in `build_router` (ensure /api/subnets/utilization and /api/subnets/suggestions are registered before /api/subnets/:id to avoid path conflicts)
    - Both endpoints require auth
    - _Requirements: 6.1, 7.1, 7.3_

- [ ] 9. WireGuard API endpoint and router detail update
  - [~] 9.1 Add WireGuard endpoint and update router detail in `src/routes.rs`
    - `get_router_wireguard` — GET /api/routers/:id/wireguard, return WireguardDataResponse (404 if router not found)
    - Update `get_router_detail` to fetch and include wireguard_interfaces and wireguard_peers in response
    - Register /api/routers/:id/wireguard route in `build_router`
    - Require auth
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 9.3_

- [~] 10. Checkpoint
  - Ensure all code compiles and routes are wired correctly, ask the user if questions arise.

- [ ] 11. Frontend — Subnet Overview section
  - [~] 11.1 Add Subnet Overview navigation and dashboard to `static/index.html`
    - Add "Subnet Overview" item to the main navigation
    - Create subnet overview section/view with: list of subnets as cards/rows showing CIDR, label, utilization bar, used count, available count
    - Fetch data from GET /api/subnets/utilization on section load
    - Add click-to-expand detail showing individual used IPs with source and router name
    - _Requirements: 8.1, 8.2, 8.3_

  - [~] 11.2 Add subnet management form and suggestions display
    - Add "Add Subnet" form with CIDR and label fields, client-side CIDR validation
    - POST to /api/subnets on submit, refresh list on success
    - Add edit and delete buttons on each subnet row (PUT/DELETE /api/subnets/:id)
    - Display suggested subnets from GET /api/subnets/suggestions with one-click "Add" action
    - _Requirements: 8.4, 8.5, 8.6_

- [ ] 12. Frontend — WireGuard in router detail
  - [~] 12.1 Add WireGuard section to router detail view in `static/index.html`
    - Add "WireGuard" section/tab in the router detail modal/page
    - Display interfaces: name, listen-port, public-key (truncated to 8 chars + ...), running status badge, disabled status
    - Display peers grouped by interface: public-key (truncated), allowed-address, current-endpoint, last-handshake, rx/tx bytes (human-readable)
    - Data comes from the updated GET /api/routers/:id/detail response (wireguard_interfaces + wireguard_peers fields)
    - Show "No WireGuard data" if arrays are empty
    - _Requirements: 9.1, 9.2, 9.3_

- [~] 13. Final checkpoint
  - Ensure all code compiles, all routes work together, frontend renders correctly. Ask the user if questions arise.

## Notes

- All backend code is Rust (Axum + SQLx + SQLite)
- Frontend is a single-page `static/index.html` with vanilla JS
- WireGuard fetch failures are non-fatal — scan continues with empty WG data
- The `ipnet` crate is already a dependency and handles CIDR parsing
- No property-based tests per user request (cargo unavailable on Windows dev machine)
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "3.1"] },
    { "id": 2, "tasks": ["2.1", "2.2", "4.1"] },
    { "id": 3, "tasks": ["4.2", "6.1"] },
    { "id": 4, "tasks": ["6.2", "7.1"] },
    { "id": 5, "tasks": ["8.1", "9.1"] },
    { "id": 6, "tasks": ["11.1", "12.1"] },
    { "id": 7, "tasks": ["11.2"] }
  ]
}
```
