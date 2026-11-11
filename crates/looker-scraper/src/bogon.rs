use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Checks if an IP address belongs to bogon, private, reserved, loopback, or multicast space.
///
/// Bogons should never be probed or routed over public proxy networks.
pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_bogon_v4(v4),
        IpAddr::V6(v6) => is_bogon_v6(v6),
    }
}

pub fn is_valid_public_ip(ip: IpAddr) -> bool {
    !is_bogon(ip)
}

fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8 (Current network)
    if octets[0] == 0 {
        return true;
    }

    // 10.0.0.0/8 (Private-Use RFC 1918)
    if octets[0] == 10 {
        return true;
    }

    // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }

    // 127.0.0.0/8 (Loopback RFC 1122)
    if octets[0] == 127 {
        return true;
    }

    // 169.254.0.0/16 (Link Local RFC 3927)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 172.16.0.0/12 (Private-Use RFC 1918)
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }

    // 192.0.0.0/24 (IETF Protocol Assignments RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }

    // 192.0.2.0/24 (TEST-NET-1 RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }

    // 192.168.0.0/16 (Private-Use RFC 1918)
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 198.18.0.0/15 (Network Interconnect Device Benchmark RFC 2544)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // 198.51.100.0/24 (TEST-NET-2 RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 (TEST-NET-3 RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // 224.0.0.0/4 (Multicast RFC 5771)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // 240.0.0.0/4 (Reserved for Future Use RFC 1112)
    if octets[0] >= 240 {
        return true;
    }

    // 255.255.255.255 (Limited Broadcast)
    if ip == Ipv4Addr::BROADCAST {
        return true;
    }

    false
}

fn is_bogon_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    // ::/128 (Unspecified)
    if ip.is_unspecified() {
        return true;
    }

    // ::1/128 (Loopback)
    if ip.is_loopback() {
        return true;
    }

    // ::ffff:0:0/96 (IPv4-mapped address)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_bogon_v4(v4);
    }

    // 100::/64 (Discard-Only RFC 6666)
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }

    // 2001:db8::/32 (Documentation RFC 3849)
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // fc00::/7 (Unique Local Address RFC 4193)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // fe80::/10 (Link-Local Unicast RFC 4291)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // ff00::/8 (Multicast RFC 4291)
    if (segments[0] & 0xff00) == 0xff00 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogons_v4() {
        assert!(is_bogon("127.0.0.1".parse().unwrap()));
        assert!(is_bogon("10.0.0.1".parse().unwrap()));
        assert!(is_bogon("192.168.1.1".parse().unwrap()));
        assert!(is_bogon("172.16.0.1".parse().unwrap()));
        assert!(is_bogon("172.31.255.255".parse().unwrap()));
        assert!(is_bogon("169.254.1.1".parse().unwrap()));
        assert!(is_bogon("0.0.0.0".parse().unwrap()));
        assert!(is_bogon("224.0.0.1".parse().unwrap()));
        assert!(is_bogon("245.0.0.1".parse().unwrap()));

        // Public IPs
        assert!(!is_bogon("1.1.1.1".parse().unwrap()));
        assert!(!is_bogon("8.8.8.8".parse().unwrap()));
        assert!(!is_bogon("104.26.10.1".parse().unwrap()));
    }
}
