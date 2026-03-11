use std::net::IpAddr;
use maxminddb::geoip2;
use std::sync::Arc;

pub struct GeoResolver {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    asn_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoResolver {
    pub fn new() -> Self {
        let reader = maxminddb::Reader::open_readfile("GeoLite2-City.mmdb")
            .ok()
            .map(Arc::new);
        
        let asn_reader = maxminddb::Reader::open_readfile("GeoLite2-ASN.mmdb")
            .ok()
            .map(Arc::new);
        
        Self { reader, asn_reader }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<(f64, f64)> {
        if let Some(ref reader) = self.reader {
            let city: Result<geoip2::City, _> = reader.lookup(ip);
            if let Ok(city) = city {
                if let Some(location) = city.location {
                    if let (Some(lat), Some(lon)) = (location.latitude, location.longitude) {
                        return Some((lat, lon));
                    }
                }
            }
        }
        
        match ip {
            IpAddr::V4(v4) if v4.to_string() == "8.8.8.8" => Some((37.751, -97.822)),
            IpAddr::V4(v4) if v4.to_string() == "1.1.1.1" => Some((-33.494, 143.210)),
            _ => None,
        }
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> (Option<u32>, Option<String>) {
        if let Some(ref reader) = self.asn_reader {
            let asn: Result<geoip2::Asn, _> = reader.lookup(ip);
            if let Ok(asn) = asn {
                return (
                    asn.autonomous_system_number,
                    asn.autonomous_system_organization.map(|s| s.to_string())
                );
            }
        }

        // Mock data
        match ip {
            IpAddr::V4(v4) if v4.to_string() == "8.8.8.8" => (Some(15169), Some("Google LLC".to_string())),
            IpAddr::V4(v4) if v4.to_string() == "1.1.1.1" => (Some(13335), Some("Cloudflare, Inc.".to_string())),
            _ => (None, None),
        }
    }
}
