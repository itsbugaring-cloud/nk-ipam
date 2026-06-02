use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

/// Validates that the input is a well-formed CIDR (IPv4 or IPv6) with correct network address.
pub fn validate_cidr(input: &str) -> Result<IpNet, String> {
    let trimmed = input.trim();
    let net: IpNet = trimmed
        .parse()
        .map_err(|e| format!("invalid CIDR: {e}"))?;
    // Ensure the host bits are zeroed (it's a proper network address)
    let trunc = net.trunc();
    if trunc != net {
        return Err(format!(
            "CIDR has non-zero host bits; did you mean {}?",
            trunc
        ));
    }
    Ok(net)
}

/// Checks if an IP is within the subnet, excluding network and broadcast for IPv4.
pub fn ip_in_subnet(ip: IpAddr, net: &IpNet) -> bool {
    if !net.contains(&ip) {
        return false;
    }
    // For IPv4, exclude network and broadcast addresses (only for prefix < 31)
    if let (IpAddr::V4(v4), IpNet::V4(v4net)) = (ip, net) {
        let prefix = v4net.prefix_len();
        if prefix < 31 {
            let network_addr = v4net.network();
            let broadcast_addr = v4net.broadcast();
            if v4 == network_addr || v4 == broadcast_addr {
                return false;
            }
        }
    }
    true
}

/// Computes the total number of usable host addresses in a subnet.
/// For IPv4: 2^host_bits - 2 (excluding network and broadcast). Minimum 0 for /31 and /32.
/// For IPv6: 2^host_bits (capped at u64::MAX).
pub fn total_hosts(net: &IpNet) -> u64 {
    match net {
        IpNet::V4(v4net) => {
            let prefix = v4net.prefix_len();
            if prefix >= 31 {
                // /31 = 2 usable (point-to-point), /32 = 1 usable
                2u64.saturating_pow(32 - prefix as u32)
            } else {
                let host_bits = 32 - prefix as u32;
                2u64.pow(host_bits) - 2
            }
        }
        IpNet::V6(v6net) => {
            let prefix = v6net.prefix_len();
            let host_bits = 128 - prefix as u32;
            if host_bits >= 64 {
                u64::MAX
            } else {
                2u64.pow(host_bits)
            }
        }
    }
}

/// Expands an IPv4 range (start..=end) and returns IPs that fall within the given subnet.
/// Capped at 1024 IPs per range to prevent memory issues.
pub fn expand_range_in_subnet(start: Ipv4Addr, end: Ipv4Addr, net: &IpNet) -> Vec<IpAddr> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    if end_u32 < start_u32 {
        return Vec::new();
    }
    let count = (end_u32 - start_u32 + 1).min(1024);
    let mut result = Vec::new();
    for i in 0..count {
        let ip = Ipv4Addr::from(start_u32 + i);
        let addr = IpAddr::V4(ip);
        if ip_in_subnet(addr, net) {
            result.push(addr);
        }
    }
    result
}

#[derive(Debug, Clone)]
pub enum AddressScope {
    Cidr(IpNet),
    Range(Ipv4Addr, Ipv4Addr),
}

impl AddressScope {
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (AddressScope::Cidr(net), ip) => net.contains(&ip),
            (AddressScope::Range(start, end), IpAddr::V4(ipv4)) => ipv4 >= *start && ipv4 <= *end,
            (AddressScope::Range(_, _), IpAddr::V6(_)) => false,
        }
    }
}

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

pub fn parse_scope(input: &str) -> Option<AddressScope> {
    let trimmed = input.trim();

    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Some(AddressScope::Cidr(net));
    }

    if let Some((start, end)) = trimmed.split_once('-') {
        let start = start.trim().parse::<Ipv4Addr>().ok()?;
        let end = end.trim().parse::<Ipv4Addr>().ok()?;
        return Some(AddressScope::Range(start, end));
    }

    None
}

pub fn ranges_to_scopes(raw_ranges: &str) -> Vec<AddressScope> {
    raw_ranges
        .split(',')
        .filter_map(parse_scope)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{extract_host_ip, parse_scope, AddressScope};

    #[test]
    fn parses_cidr_scope() {
        let scope = parse_scope("10.10.10.0/24").expect("cidr should parse");
        assert!(scope.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 5))));
    }

    #[test]
    fn parses_range_scope() {
        let scope = parse_scope("10.10.10.10-10.10.10.20").expect("range should parse");
        assert!(matches!(scope, AddressScope::Range(_, _)));
        assert!(scope.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 15))));
        assert!(!scope.contains_ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 30))));
    }

    #[test]
    fn extract_host_ip_with_cidr_prefix() {
        let result = extract_host_ip("192.168.5.254/24");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 254))));
    }

    #[test]
    fn extract_host_ip_without_prefix() {
        let result = extract_host_ip("10.0.0.1");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn extract_host_ip_invalid_string() {
        assert_eq!(extract_host_ip("not-an-ip"), None);
        assert_eq!(extract_host_ip(""), None);
        assert_eq!(extract_host_ip("abc/24"), None);
    }

    #[test]
    fn extract_host_ip_ipv6_with_prefix() {
        let result = extract_host_ip("fe80::1/64");
        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn extract_host_ip_ipv6_without_prefix() {
        let result = extract_host_ip("::1");
        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn extract_host_ip_trims_whitespace() {
        let result = extract_host_ip("  192.168.1.1/32  ");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }
}
