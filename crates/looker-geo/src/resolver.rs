use std::net::IpAddr;
use std::path::Path;

use crate::error::GeoError;
use crate::types::GeoInfo;

/// Zero-copy offline MaxMind GeoLite2 reader.
///
/// Uses memory-mapped files via `memmap2` and `maxminddb` to provide fast,
/// lock-free synchronous lookups without reading entire databases into RAM or
/// spawning blocking tasks for single queries.
pub struct GeoResolver {
    city_reader: Option<maxminddb::Reader<memmap2::Mmap>>,
    asn_reader: Option<maxminddb::Reader<memmap2::Mmap>>,
}

impl Default for GeoResolver {
    fn default() -> Self {
        Self::empty()
    }
}

impl GeoResolver {
    /// Creates a resolver with no databases loaded (queries return None/defaults).
    pub fn empty() -> Self {
        Self {
            city_reader: None,
            asn_reader: None,
        }
    }

    /// Loads memory-mapped City and ASN databases from the specified paths.
    pub fn from_paths<P: AsRef<Path>>(
        city_path: Option<P>,
        asn_path: Option<P>,
    ) -> Result<Self, GeoError> {
        let city_reader = match city_path {
            Some(path) => {
                let p = path.as_ref();
                if p.exists() {
                    let r = unsafe { maxminddb::Reader::open_mmap(p)? };
                    Some(r)
                } else {
                    return Err(GeoError::NotFound(p.display().to_string()));
                }
            }
            None => None,
        };

        let asn_reader = match asn_path {
            Some(path) => {
                let p = path.as_ref();
                if p.exists() {
                    let r = unsafe { maxminddb::Reader::open_mmap(p)? };
                    Some(r)
                } else {
                    return Err(GeoError::NotFound(p.display().to_string()));
                }
            }
            None => None,
        };

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    /// Fast zero-copy synchronous lookup for country ISO 3166-1 alpha-2 code.
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;
        let res = reader.lookup(ip).ok()?;
        let city: maxminddb::geoip2::City = res.decode().ok()??;
        city.country.iso_code.map(ToString::to_string)
    }

    /// Fast zero-copy synchronous lookup for city name in English.
    pub fn city_name(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;
        let res = reader.lookup(ip).ok()?;
        let city: maxminddb::geoip2::City = res.decode().ok()??;
        city.city.names.english.map(ToString::to_string)
    }

    /// Fast zero-copy synchronous lookup for Autonomous System Number.
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn_reader.as_ref()?;
        let res = reader.lookup(ip).ok()?;
        let asn_record: maxminddb::geoip2::Asn = res.decode().ok()??;
        asn_record.autonomous_system_number
    }

    /// Fast zero-copy synchronous lookup for Autonomous System Organization name.
    pub fn asn_org(&self, ip: IpAddr) -> Option<String> {
        let reader = self.asn_reader.as_ref()?;
        let res = reader.lookup(ip).ok()?;
        let asn_record: maxminddb::geoip2::Asn = res.decode().ok()??;
        asn_record
            .autonomous_system_organization
            .map(ToString::to_string)
    }

    /// Combines city and ASN lookups into a unified `GeoInfo` struct.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let mut info = GeoInfo::default();

        if let Some(reader) = self.city_reader.as_ref() {
            if let Ok(res) = reader.lookup(ip) {
                if let Ok(Some(city)) = res.decode::<maxminddb::geoip2::City>() {
                    info.country_code = city.country.iso_code.map(ToString::to_string);
                    info.country_name = city.country.names.english.map(ToString::to_string);
                    info.city = city.city.names.english.map(ToString::to_string);
                }
            }
        }

        if let Some(reader) = self.asn_reader.as_ref() {
            if let Ok(res) = reader.lookup(ip) {
                if let Ok(Some(asn_record)) = res.decode::<maxminddb::geoip2::Asn>() {
                    info.asn = asn_record.autonomous_system_number;
                    info.asn_org = asn_record
                        .autonomous_system_organization
                        .map(ToString::to_string);
                }
            }
        }

        info
    }
}
