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
    use std::net::{IpAddr, Ipv4Addr};

    use super::{parse_scope, AddressScope};

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
}
