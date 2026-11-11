use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GeoInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        self.country_code.is_none()
            && self.country_name.is_none()
            && self.city.is_none()
            && self.asn.is_none()
            && self.asn_org.is_none()
    }
}

impl fmt::Display for GeoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let country = self.country_code.as_deref().unwrap_or("??");
        let city = self.city.as_deref().unwrap_or("Unknown");
        let asn = self
            .asn
            .map(|a| format!("AS{}", a))
            .unwrap_or_else(|| "AS-".to_string());
        let org = self.asn_org.as_deref().unwrap_or("Unknown Org");
        write!(f, "{}/{} ({}, {})", country, city, asn, org)
    }
}
