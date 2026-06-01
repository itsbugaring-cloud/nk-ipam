# Tasks

## Task 1: Database Migration for Router Addresses

- [x] 1.1 Create `migrations/0002_router_addresses.sql` with the `router_addresses` table schema (columns: id, router_id, address, interface, network, created_at, updated_at) and index on router_id
- [x] 1.2 Verify migration runs successfully against existing SQLite database

## Task 2: Add Data Models

- [x] 2.1 Add `RouterApiAddress` struct to `src/models.rs` with fields: address (String), interface (String), network (Option<String>) and Deserialize/Serialize derives
- [x] 2.2 Add `RouterAddressRecord` struct to `src/models.rs` with fields: id, router_id, address, interface, network, created_at, updated_at and FromRow derive

## Task 3: Add MikroTik Client Method

- [x] 3.1 Add `fetch_addresses()` method to `MikrotikClient` in `src/mikrotik.rs` that calls `GET /rest/ip/address` and returns `Vec<RouterApiAddress>`

## Task 4: Add IP Extraction Utility

- [x] 4.1 Add `extract_host_ip()` function to `src/net.rs` that strips CIDR prefix and returns `Option<IpAddr>`
- [x] 4.2 [PBT] Write property test: for any valid IP and prefix length, `extract_host_ip("{ip}/{prefix}")` returns `Some(ip)`
- [x] 4.3 Add unit tests for edge cases: address without prefix, invalid strings, IPv6 addresses

## Task 5: Update OLT Mapping Logic

- [x] 5.1 Update `find_matching_olt()` signature in `src/routes.rs` to accept `&[RouterApiAddress]` as first matching source
- [x] 5.2 Implement address-priority matching: check interface IPs first (return `auto_address`), then routes (`auto_route`), then pools (`auto_pool`)
- [x] 5.3 [PBT] Write property test: when an OLT IP exists in both interface addresses and route scopes, mapping source is always `auto_address`
- [x] 5.4 [PBT] Write property test: when OLT IP is only in routes (not addresses), result is `auto_route`; when only in pools, result is `auto_pool`; when in none, result is `None`

## Task 6: Update Scan Flow

- [x] 6.1 Add `fetch_addresses()` call to `scan_router_payload()` in `src/routes.rs`, before pool/route fetching
- [x] 6.2 Implement `replace_router_addresses()` helper function to delete-and-reinsert address records for a router
- [x] 6.3 Pass fetched addresses to the updated `find_matching_olt()` call
- [x] 6.4 Handle fetch_addresses errors consistently with existing pool/route error handling

## Task 7: Update Router Detail API

- [x] 7.1 Add `addresses: Vec<RouterAddressRecord>` field to `RouterDetailResponse` in `src/models.rs`
- [x] 7.2 Update `get_router_detail()` handler to query and include `router_addresses` records in the response

## Task 8: Update Frontend

- [x] 8.1 Add "Interface Addresses" section to the router detail view in `static/index.html` displaying a table with Interface, Address, and Network columns
- [x] 8.2 Handle empty state when no interface addresses are available
- [x] 8.3 Update mapping source display to show `auto_address` label with appropriate description alongside existing `auto_route` and `auto_pool` labels
