pub mod error;
pub mod resolver;
pub mod types;

pub use error::GeoError;
pub use resolver::GeoResolver;
pub use types::GeoInfo;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_empty_resolver() {
        let resolver = GeoResolver::empty();
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        assert_eq!(resolver.country_code(ip), None);
        assert_eq!(resolver.city_name(ip), None);
        assert_eq!(resolver.asn(ip), None);
        assert_eq!(resolver.asn_org(ip), None);

        let info = resolver.lookup(ip);
        assert!(info.is_empty());
    }
}
