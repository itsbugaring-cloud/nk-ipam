use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use sqlx::SqlitePool;

use crate::app_error::AppResult;
use crate::models::{
    IpPoolRecord, IpSource, RouterAddressRecord, RouterRecord, SubnetDefinitionRecord,
    SubnetSuggestion, SubnetUtilization, UsedIpEntry, WireguardPeerRecord,
};
use crate::net::{expand_range_in_subnet, extract_host_ip, ip_in_subnet, total_hosts, validate_cidr};

/// Computes IP utilization for each defined subnet by aggregating used IPs
/// from router_addresses, ip_pools, and wireguard_peers.
pub async fn compute_utilization(
    pool: &SqlitePool,
    subnets: &[SubnetDefinitionRecord],
) -> AppResult<Vec<SubnetUtilization>> {
    if subnets.is_empty() {
        return Ok(Vec::new());
    }

    // Load all data in bulk
    let routers = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers")
        .fetch_all(pool)
        .await?;
    let addresses = sqlx::query_as::<_, RouterAddressRecord>("SELECT * FROM router_addresses")
        .fetch_all(pool)
        .await?;
    let ip_pools = sqlx::query_as::<_, IpPoolRecord>("SELECT * FROM ip_pools")
        .fetch_all(pool)
        .await?;
    let wg_peers = sqlx::query_as::<_, WireguardPeerRecord>("SELECT * FROM wireguard_peers")
        .fetch_all(pool)
        .await?;

    // Build router name lookup
    let router_names: HashMap<i64, String> = routers
        .iter()
        .map(|r| (r.id, r.name.clone()))
        .collect();

    let mut results = Vec::with_capacity(subnets.len());

    for subnet in subnets {
        let net = match subnet.cidr.parse::<IpNet>() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let subnet_total = total_hosts(&net);
        let mut used_map: HashMap<IpAddr, Vec<IpSource>> = HashMap::new();

        // Source 1: Router addresses
        for addr in &addresses {
            if let Some(ip) = extract_host_ip(&addr.address) {
                if ip_in_subnet(ip, &net) {
                    let router_name = router_names
                        .get(&addr.router_id)
                        .cloned()
                        .unwrap_or_default();
                    used_map.entry(ip).or_default().push(IpSource {
                        source_type: "address".to_string(),
                        router_id: addr.router_id,
                        router_name,
                        detail: Some(addr.interface.clone()),
                    });
                }
            }
        }

        // Source 2: IP pool ranges
        for ip_pool in &ip_pools {
            let router_name = router_names
                .get(&ip_pool.router_id)
                .cloned()
                .unwrap_or_default();
            for scope in crate::net::ranges_to_scopes(&ip_pool.raw_ranges) {
                match scope {
                    crate::net::AddressScope::Cidr(pool_net) => {
                        // For CIDR pools, only iterate if reasonably sized (IPv4 only)
                        if let IpNet::V4(v4net) = pool_net {
                            let pool_hosts = total_hosts(&IpNet::V4(v4net));
                            if pool_hosts <= 1024 {
                                for host in v4net.hosts() {
                                    let addr = IpAddr::V4(host);
                                    if ip_in_subnet(addr, &net) {
                                        used_map.entry(addr).or_default().push(IpSource {
                                            source_type: "pool".to_string(),
                                            router_id: ip_pool.router_id,
                                            router_name: router_name.clone(),
                                            detail: Some(ip_pool.pool_name.clone()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    crate::net::AddressScope::Range(start, end) => {
                        let ips = expand_range_in_subnet(start, end, &net);
                        for ip in ips {
                            used_map.entry(ip).or_default().push(IpSource {
                                source_type: "pool".to_string(),
                                router_id: ip_pool.router_id,
                                router_name: router_name.clone(),
                                detail: Some(ip_pool.pool_name.clone()),
                            });
                        }
                    }
                }
            }
        }

        // Source 3: WireGuard peer allowed-addresses
        for peer in &wg_peers {
            if let Some(allowed) = &peer.allowed_address {
                let router_name = router_names
                    .get(&peer.router_id)
                    .cloned()
                    .unwrap_or_default();
                for addr_str in allowed.split(',') {
                    if let Some(ip) = extract_host_ip(addr_str.trim()) {
                        if ip_in_subnet(ip, &net) {
                            let detail = peer
                                .public_key
                                .as_deref()
                                .map(|k| {
                                    if k.len() > 8 {
                                        format!("{}...", &k[..8])
                                    } else {
                                        k.to_string()
                                    }
                                });
                            used_map.entry(ip).or_default().push(IpSource {
                                source_type: "wireguard_peer".to_string(),
                                router_id: peer.router_id,
                                router_name: router_name.clone(),
                                detail,
                            });
                        }
                    }
                }
            }
        }

        let used_count = used_map.len() as u64;
        let available_count = subnet_total.saturating_sub(used_count);
        let utilization_pct = if subnet_total > 0 {
            (used_count as f64 / subnet_total as f64) * 100.0
        } else {
            0.0
        };

        let mut used_ips: Vec<UsedIpEntry> = used_map
            .into_iter()
            .map(|(ip, sources)| UsedIpEntry {
                ip: ip.to_string(),
                sources,
            })
            .collect();
        used_ips.sort_by(|a, b| a.ip.cmp(&b.ip));

        results.push(SubnetUtilization {
            id: subnet.id,
            cidr: subnet.cidr.clone(),
            label: subnet.label.clone(),
            total_hosts: subnet_total,
            used_count,
            available_count,
            utilization_pct,
            used_ips,
        });
    }

    Ok(results)
}

/// Computes subnet suggestions by extracting CIDRs from all sources and
/// filtering out those that already exist in subnet_definitions.
pub async fn compute_suggestions(
    pool: &SqlitePool,
    existing: &[SubnetDefinitionRecord],
) -> AppResult<Vec<SubnetSuggestion>> {
    let existing_cidrs: std::collections::HashSet<String> = existing
        .iter()
        .map(|s| s.cidr.clone())
        .collect();

    let routers = sqlx::query_as::<_, RouterRecord>("SELECT * FROM routers")
        .fetch_all(pool)
        .await?;
    let router_names: HashMap<i64, String> = routers
        .iter()
        .map(|r| (r.id, r.name.clone()))
        .collect();

    let addresses = sqlx::query_as::<_, RouterAddressRecord>("SELECT * FROM router_addresses")
        .fetch_all(pool)
        .await?;
    let ip_pools = sqlx::query_as::<_, IpPoolRecord>("SELECT * FROM ip_pools")
        .fetch_all(pool)
        .await?;
    let routes = sqlx::query_as::<_, crate::models::RouterRouteRecord>("SELECT * FROM router_routes")
        .fetch_all(pool)
        .await?;
    let wg_peers = sqlx::query_as::<_, WireguardPeerRecord>("SELECT * FROM wireguard_peers")
        .fetch_all(pool)
        .await?;

    // Track discovered CIDRs to avoid duplicates in suggestions
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut suggestions = Vec::new();

    // From router_addresses.network field
    for addr in &addresses {
        if let Some(network) = &addr.network {
            if let Ok(net) = validate_cidr(network) {
                let cidr = net.to_string();
                if !existing_cidrs.contains(&cidr) && seen.insert(cidr.clone()) {
                    let router_name = router_names
                        .get(&addr.router_id)
                        .cloned()
                        .unwrap_or_else(|| format!("Router-{}", addr.router_id));
                    suggestions.push(SubnetSuggestion {
                        cidr,
                        proposed_label: format!("From address on {}", router_name),
                        source_description: format!("router_address.network on {}", router_name),
                    });
                }
            }
        }
    }

    // From ip_pools.derived_network field
    for ip_pool in &ip_pools {
        if let Some(derived) = &ip_pool.derived_network {
            if let Ok(net) = validate_cidr(derived) {
                let cidr = net.to_string();
                if !existing_cidrs.contains(&cidr) && seen.insert(cidr.clone()) {
                    let router_name = router_names
                        .get(&ip_pool.router_id)
                        .cloned()
                        .unwrap_or_else(|| format!("Router-{}", ip_pool.router_id));
                    suggestions.push(SubnetSuggestion {
                        cidr,
                        proposed_label: format!("From pool {} on {}", ip_pool.pool_name, router_name),
                        source_description: format!("ip_pool.derived_network on {}", router_name),
                    });
                }
            }
        }
    }

    // From router_routes.dst_address field
    for route in &routes {
        if let Some(dst) = &route.dst_address {
            if let Ok(net) = validate_cidr(dst) {
                let cidr = net.to_string();
                if !existing_cidrs.contains(&cidr) && seen.insert(cidr.clone()) {
                    let router_name = router_names
                        .get(&route.router_id)
                        .cloned()
                        .unwrap_or_else(|| format!("Router-{}", route.router_id));
                    suggestions.push(SubnetSuggestion {
                        cidr,
                        proposed_label: format!("From route on {}", router_name),
                        source_description: format!("router_route.dst_address on {}", router_name),
                    });
                }
            }
        }
    }

    // From wireguard_peers.allowed_address field
    for peer in &wg_peers {
        if let Some(allowed) = &peer.allowed_address {
            for addr_str in allowed.split(',') {
                let trimmed = addr_str.trim();
                if let Ok(net) = validate_cidr(trimmed) {
                    let cidr = net.to_string();
                    if !existing_cidrs.contains(&cidr) && seen.insert(cidr.clone()) {
                        let router_name = router_names
                            .get(&peer.router_id)
                            .cloned()
                            .unwrap_or_else(|| format!("Router-{}", peer.router_id));
                        suggestions.push(SubnetSuggestion {
                            cidr,
                            proposed_label: format!("From WireGuard peer on {}", router_name),
                            source_description: format!("wireguard_peer.allowed_address on {}", router_name),
                        });
                    }
                }
            }
        }
    }

    Ok(suggestions)
}
