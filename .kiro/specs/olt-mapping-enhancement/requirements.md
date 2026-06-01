# Requirements Document

## Introduction

This feature corrects and enhances the OLT auto-mapping logic in Netking IPAM. The current implementation incorrectly matches OLT IPs against router IP routes (customer subnets) and IP pools, causing false positives. The correct approach is to fetch `/rest/ip/address` from MikroTik routers and match OLT IPs against addresses assigned to the router's interfaces. Route and pool matching are retained as lower-priority fallback methods.

## Glossary

- **IPAM_System**: The Netking IPAM application (Rust + Axum + SQLite backend with vanilla JS frontend)
- **MikroTik_Client**: The HTTP client module (`src/mikrotik.rs`) that communicates with MikroTik RouterOS REST API
- **OLT**: Optical Line Terminal device, imported from bookmarks with a name and IP address
- **Router**: A MikroTik router accessed via WireGuard IP using the RouterOS REST API
- **IP_Address_Entry**: A record returned by the MikroTik `/rest/ip/address` endpoint, containing an address (IP/prefix), interface name, and network
- **Mapping_Engine**: The logic that determines which OLT is associated with a given router based on IP address matching
- **Auto_Address_Mapping**: A mapping established by matching an OLT IP against a router's interface addresses (highest priority)
- **Auto_Route_Mapping**: A mapping established by matching an OLT IP against a router's IP routes (lower priority fallback)
- **Auto_Pool_Mapping**: A mapping established by matching an OLT IP against a router's IP pool ranges (lowest priority fallback)

## Requirements

### Requirement 1: Fetch IP Addresses from MikroTik Router

**User Story:** As a network administrator, I want the system to fetch IP addresses assigned to router interfaces, so that OLT mapping uses the correct data source.

#### Acceptance Criteria

1. WHEN a router scan is initiated, THE MikroTik_Client SHALL send an HTTP GET request to `/rest/ip/address` on the target router
2. WHEN the `/rest/ip/address` endpoint returns a successful response, THE MikroTik_Client SHALL deserialize the JSON array into a list of IP_Address_Entry records containing at minimum the `address` and `interface` fields
3. IF the `/rest/ip/address` endpoint returns a non-success HTTP status, THEN THE MikroTik_Client SHALL return an error containing the HTTP status code and response body
4. IF the `/rest/ip/address` endpoint is unreachable or times out, THEN THE MikroTik_Client SHALL propagate the connection error to the caller

### Requirement 2: Parse IP Address Entries

**User Story:** As a network administrator, I want the system to correctly parse IP address entries from MikroTik, so that the mapping logic can compare them against OLT IPs.

#### Acceptance Criteria

1. WHEN an IP_Address_Entry contains an address in CIDR format (e.g., `192.168.5.254/24`), THE IPAM_System SHALL extract the host IP by stripping the prefix length
2. WHEN an IP_Address_Entry contains an address without a prefix (e.g., `192.168.5.254`), THE IPAM_System SHALL use the address as-is for matching
3. THE IPAM_System SHALL parse both IPv4 and IPv6 address formats from IP_Address_Entry records

### Requirement 3: Primary OLT Mapping via Interface Addresses

**User Story:** As a network administrator, I want OLTs to be mapped to routers based on interface addresses, so that mappings are accurate and reflect the actual network topology.

#### Acceptance Criteria

1. WHEN a router scan completes successfully, THE Mapping_Engine SHALL check each OLT IP against the set of host IPs extracted from the router's IP_Address_Entry records
2. WHEN an OLT IP exactly matches a host IP from the router's interface addresses, THE Mapping_Engine SHALL create an Auto_Address_Mapping with mapping source `auto_address`
3. WHEN an Auto_Address_Mapping is found, THE Mapping_Engine SHALL select that mapping without evaluating route or pool fallbacks
4. THE Mapping_Engine SHALL evaluate Auto_Address_Mapping before Auto_Route_Mapping and Auto_Pool_Mapping

### Requirement 4: Fallback OLT Mapping via Routes and Pools

**User Story:** As a network administrator, I want route and pool matching retained as fallback methods, so that routers without direct OLT interface addresses can still be mapped.

#### Acceptance Criteria

1. WHEN no Auto_Address_Mapping is found, THE Mapping_Engine SHALL evaluate OLT IPs against route destination addresses to produce an Auto_Route_Mapping
2. WHEN no Auto_Address_Mapping and no Auto_Route_Mapping is found, THE Mapping_Engine SHALL evaluate OLT IPs against IP pool ranges to produce an Auto_Pool_Mapping
3. THE Mapping_Engine SHALL assign priority order: Auto_Address_Mapping (highest), Auto_Route_Mapping (second), Auto_Pool_Mapping (lowest)

### Requirement 5: Store Router Interface Addresses

**User Story:** As a network administrator, I want router interface addresses persisted in the database, so that I can inspect them and the system can reference them without re-scanning.

#### Acceptance Criteria

1. WHEN a router scan fetches IP_Address_Entry records, THE IPAM_System SHALL store each entry in the database associated with the scanned router
2. WHEN a subsequent scan is performed for the same router, THE IPAM_System SHALL replace previously stored IP_Address_Entry records with the new set
3. THE IPAM_System SHALL store the address (full CIDR notation), interface name, and network field for each IP_Address_Entry record

### Requirement 6: Display Router Interface Addresses in UI

**User Story:** As a network administrator, I want to see the interface addresses assigned to a router in the detail view, so that I can verify the mapping data source.

#### Acceptance Criteria

1. WHEN a user views a router's detail page, THE IPAM_System SHALL display the list of stored IP_Address_Entry records for that router
2. THE IPAM_System SHALL display the interface name and address for each IP_Address_Entry record
3. WHEN a router has no stored IP_Address_Entry records, THE IPAM_System SHALL display an empty state indicating no interface addresses are available

### Requirement 7: Mapping Source Visibility

**User Story:** As a network administrator, I want to see how each router-OLT mapping was determined, so that I can understand and trust the auto-mapping results.

#### Acceptance Criteria

1. THE IPAM_System SHALL display the mapping source (`auto_address`, `auto_route`, `auto_pool`, or `manual`) alongside each router-OLT mapping in the explorer view
2. WHEN a mapping source is `auto_address`, THE IPAM_System SHALL indicate that the mapping was determined by interface address match
3. WHEN a mapping source is `auto_route` or `auto_pool`, THE IPAM_System SHALL indicate that the mapping was determined by a fallback method
