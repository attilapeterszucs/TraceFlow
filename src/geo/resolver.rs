use std::net::IpAddr;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

pub struct DnsResolver {
    resolver: Resolver,
}

impl DnsResolver {
    pub fn new() -> Self {
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        Self { resolver }
    }

    pub fn resolve_ip(&self, ip: IpAddr) -> Option<String> {
        match self.resolver.reverse_lookup(ip) {
            Ok(lookup) => {
                // Get the first PTR record
                lookup.iter().next().map(|name| name.to_utf8().trim_end_matches('.').to_string())
            }
            Err(_) => None,
        }
    }
}
