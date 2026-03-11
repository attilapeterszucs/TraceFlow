// Utility functions for networking (e.g., checksums, IP parsing)

use std::net::IpAddr;

pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || (ipv6.segments()[0] & 0xfe00) == 0xfc00,
    }
}
