use std::net::IpAddr;
use maxminddb::geoip2;
use std::sync::Arc;

pub struct GeoResolver {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoResolver {
    pub fn new() -> Self {
        // Try to load the database if it exists, otherwise fallback to mock
        let reader = maxminddb::Reader::open_readfile("GeoLite2-City.mmdb")
            .ok()
            .map(Arc::new);
        
        Self { reader }
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
        
        // Mock data for common IPs if DB is missing
        match ip {
            IpAddr::V4(v4) if v4.to_string() == "8.8.8.8" => Some((37.751, -97.822)),
            IpAddr::V4(v4) if v4.to_string() == "1.1.1.1" => Some((-33.494, 143.210)),
            _ => None,
        }
    }
}
