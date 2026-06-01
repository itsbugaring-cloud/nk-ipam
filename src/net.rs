use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

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
