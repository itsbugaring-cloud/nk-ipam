# Requirements Document

## Introduction

This feature enhances Netking IPAM with WireGuard data collection from MikroTik routers and an IP Utilization / Subnet Overview dashboard. The system will fetch WireGuard interfaces and peers via the RouterOS REST API, integrate WireGuard data into the existing bulk scan workflow, and provide a consolidated view of IP address usage across all scanned subnets. The goal is to help network operators plan new server IPs without conflicts by showing at a glance what is taken and what is free in each subnet.

## Glossary

- **IPAM_System**: The Netking IPAM backend application (Rust + Axum + SQLite)
- **MikroTik_Client**: The HTTP client module that communicates with MikroTik RouterOS REST API endpoints
- **WireGuard_Interface**: A WireGuard tunnel interface on a MikroTik router, containing name, listen-port, public-key, mtu, running status, and disabled status
- **WireGuard_Peer**: A WireGuard peer configured on a MikroTik router, containing interface, public-key, endpoint-address, endpoint-port, allowed-address, current-endpoint-address, current-endpoint-port, last-handshake, rx, and tx
- **Subnet_Definition**: A user-defined subnet entry specifying a CIDR network and a human-readable label describing its purpose (e.g., "WireGuard Transit", "PPPoE Pool")
- **IP_Utilization_View**: An aggregated view showing used and available IP addresses within each defined subnet
- **Bulk_Scanner**: The existing concurrent scan mechanism that collects data from multiple routers simultaneously
- **Router_Scan**: The process of connecting to a MikroTik router via REST API and collecting IP addresses, pools, routes, and WireGuard data

## Requirements

### Requirement 1: Fetch WireGuard Interfaces from MikroTik Routers

**User Story:** As a network operator, I want to collect WireGuard interface data from MikroTik routers, so that I can see which WireGuard tunnels are configured on each device.

#### Acceptance Criteria

1. WHEN a Router_Scan is initiated, THE MikroTik_Client SHALL send a GET request to `/rest/interface/wireguard` on the target router using the resolved credentials
2. WHEN the MikroTik router returns a successful response, THE MikroTik_Client SHALL parse the JSON response into a collection of WireGuard_Interface records containing: name, listen-port, public-key, mtu, running, and disabled fields
3. IF the MikroTik router returns an HTTP error status for the WireGuard interfaces endpoint, THEN THE IPAM_System SHALL log the error and continue the scan without failing the entire Router_Scan
4. WHEN WireGuard_Interface records are successfully fetched, THE IPAM_System SHALL store them in the `wireguard_interfaces` database table associated with the scanned router, replacing any previously stored interfaces for that router

### Requirement 2: Fetch WireGuard Peers from MikroTik Routers

**User Story:** As a network operator, I want to collect WireGuard peer data from MikroTik routers, so that I can see all peer connections and their allowed addresses for IP planning.

#### Acceptance Criteria

1. WHEN a Router_Scan is initiated, THE MikroTik_Client SHALL send a GET request to `/rest/interface/wireguard/peers` on the target router using the resolved credentials
2. WHEN the MikroTik router returns a successful response, THE MikroTik_Client SHALL parse the JSON response into a collection of WireGuard_Peer records containing: interface, public-key, endpoint-address, endpoint-port, allowed-address, current-endpoint-address, current-endpoint-port, last-handshake, rx, and tx fields
3. IF the MikroTik router returns an HTTP error status for the WireGuard peers endpoint, THEN THE IPAM_System SHALL log the error and continue the scan without failing the entire Router_Scan
4. WHEN WireGuard_Peer records are successfully fetched, THE IPAM_System SHALL store them in the `wireguard_peers` database table associated with the scanned router, replacing any previously stored peers for that router

### Requirement 3: Include WireGuard Data in Bulk Scan

**User Story:** As a network operator, I want the bulk scan to also collect WireGuard data from all routers simultaneously, so that I get complete network visibility in a single operation.

#### Acceptance Criteria

1. WHEN a bulk scan is initiated via `POST /api/routers/bulk-scan`, THE Bulk_Scanner SHALL collect WireGuard interfaces and peers from each router in addition to IP addresses, pools, and routes
2. THE Bulk_Scanner SHALL fetch WireGuard data using the same concurrency limit (MAX_SCAN_CONCURRENCY) as existing data collection
3. IF WireGuard data collection fails for a specific router during bulk scan, THEN THE Bulk_Scanner SHALL mark that router's WireGuard collection as failed in the result while still reporting the router scan as successful if addresses, pools, and routes were collected
4. WHEN a single router scan is initiated via `POST /api/routers/scan` or `POST /api/routers/:id/rescan`, THE IPAM_System SHALL also collect WireGuard interfaces and peers as part of the scan

### Requirement 4: WireGuard Data API Endpoint

**User Story:** As a frontend developer, I want an API endpoint to retrieve WireGuard data for a specific router, so that I can display tunnel and peer information in the UI.

#### Acceptance Criteria

1. WHEN a GET request is made to `/api/routers/:id/wireguard`, THE IPAM_System SHALL return the stored WireGuard_Interface and WireGuard_Peer records for the specified router
2. THE IPAM_System SHALL return the response as a JSON object with `interfaces` and `peers` arrays
3. IF the specified router ID does not exist, THEN THE IPAM_System SHALL return an HTTP 404 status with a descriptive error message
4. THE IPAM_System SHALL require authentication for the WireGuard data endpoint, consistent with existing API endpoint authorization

### Requirement 5: User-Defined Subnet Labels

**User Story:** As a network operator, I want to define and label subnets with a descriptive purpose, so that I can organize my network view by function (e.g., WireGuard Transit, PPPoE Pool, Server LAN).

#### Acceptance Criteria

1. WHEN a POST request is made to `/api/subnets` with a CIDR network and label, THE IPAM_System SHALL create a new Subnet_Definition record in the database
2. WHEN a PUT request is made to `/api/subnets/:id` with an updated label or CIDR, THE IPAM_System SHALL update the existing Subnet_Definition record
3. WHEN a DELETE request is made to `/api/subnets/:id`, THE IPAM_System SHALL remove the Subnet_Definition record from the database
4. THE IPAM_System SHALL validate that the provided CIDR is a well-formed IPv4 or IPv6 network address with a valid prefix length
5. THE IPAM_System SHALL prevent creation of duplicate Subnet_Definition records with the same CIDR network
6. WHEN a GET request is made to `/api/subnets`, THE IPAM_System SHALL return all Subnet_Definition records ordered by CIDR network

### Requirement 6: IP Utilization Calculation

**User Story:** As a network operator, I want to see which IPs are in use vs available in each subnet, so that I can plan new server IPs without conflicts.

#### Acceptance Criteria

1. WHEN a GET request is made to `/api/subnets/utilization`, THE IPAM_System SHALL compute and return IP utilization for each defined Subnet_Definition
2. THE IPAM_System SHALL aggregate used IPs from the following sources: router_addresses (interface IPs), ip_pools (pool ranges), and wireguard_peers (allowed-address fields)
3. FOR EACH Subnet_Definition, THE IPAM_System SHALL calculate: total host addresses in the subnet, count of used addresses, count of available addresses, and utilization percentage
4. THE IPAM_System SHALL include in the response for each subnet: the subnet CIDR, label, total hosts, used count, available count, utilization percentage, and a list of used IP addresses with their source (address, pool, or wireguard_peer)
5. WHEN an IP address appears in multiple sources, THE IPAM_System SHALL deduplicate it and report all sources that reference it
6. THE IPAM_System SHALL treat the network address and broadcast address of each subnet as reserved (not available for assignment)

### Requirement 7: Auto-Detect Subnets from Scanned Data

**User Story:** As a network operator, I want the system to suggest subnets based on collected data, so that I do not have to manually define every subnet I am using.

#### Acceptance Criteria

1. WHEN a GET request is made to `/api/subnets/suggestions`, THE IPAM_System SHALL analyze router_addresses, ip_pools, router_routes, and wireguard_peers to identify unique subnets present in the scanned data
2. THE IPAM_System SHALL derive subnet suggestions from: network fields in router_addresses, derived_network fields in ip_pools, dst_address fields in router_routes with CIDR notation, and allowed-address fields in wireguard_peers
3. THE IPAM_System SHALL exclude subnets that already exist as Subnet_Definition records from the suggestions list
4. THE IPAM_System SHALL return suggested subnets as a list of CIDR networks with a proposed default label based on the data source (e.g., "From router-address on Router-X", "From WireGuard peer on Router-Y")

### Requirement 8: Subnet Utilization Dashboard Frontend

**User Story:** As a network operator, I want a visual dashboard showing subnet utilization, so that I can quickly identify available IP space for new assignments.

#### Acceptance Criteria

1. THE IPAM_System SHALL serve a "Subnet Overview" section in the frontend UI accessible from the main navigation
2. THE IPAM_System SHALL display each defined subnet as a card or row showing: CIDR, label, utilization bar (percentage), used count, and available count
3. WHEN a user clicks on a subnet entry, THE IPAM_System SHALL expand or navigate to a detail view showing individual used IPs with their source and the router they belong to
4. THE IPAM_System SHALL provide a form to add new Subnet_Definition records with CIDR and label fields, with client-side validation of CIDR format
5. THE IPAM_System SHALL display suggested subnets from the auto-detection endpoint with a one-click "Add" action to create them as Subnet_Definitions
6. THE IPAM_System SHALL allow editing and deleting existing Subnet_Definitions from the dashboard

### Requirement 9: WireGuard Data Display in Router Detail

**User Story:** As a network operator, I want to see WireGuard interfaces and peers when viewing a router's detail page, so that I have full visibility into the router's tunnel configuration.

#### Acceptance Criteria

1. WHEN a user views a router detail page, THE IPAM_System SHALL display a "WireGuard" section showing all stored interfaces for that router with their name, listen-port, public-key (truncated), running status, and disabled status
2. WHEN a user views a router detail page, THE IPAM_System SHALL display all stored peers for that router grouped by interface, showing: public-key (truncated), allowed-address, current-endpoint-address, current-endpoint-port, last-handshake timestamp, rx bytes, and tx bytes
3. THE IPAM_System SHALL include WireGuard interfaces and peers in the existing `GET /api/routers/:id/detail` response alongside addresses, pools, and routes
