use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ipnet::IpNet;
use regex::Regex;

use crate::bogon::is_bogon;
use crate::error::ScraperError;
use looker_protocol::ProxyProto;

const MAX_CIDR_HOSTS: usize = 65536; // /16 maximum bound

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CandidateProxy {
    pub addr: SocketAddr,
    pub proto: Option<ProxyProto>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl CandidateProxy {
    pub fn new(addr: SocketAddr, proto: Option<ProxyProto>) -> Self {
        Self {
            addr,
            proto,
            username: None,
            password: None,
        }
    }
}

pub struct CandidateExtractor {
    url_regex: Regex,
    cidr_regex: Regex,
}

impl Default for CandidateExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateExtractor {
    pub fn new() -> Self {
        // Matches:
        // [scheme://][user:pass@]host:port
        // Supports IPv4, IPv6 ([::1]:port), and hostnames
        let url_regex = Regex::new(
            r"(?i)(?:(?P<proto>socks5h?|socks4a?|https?|connect)://)?(?:(?P<user>[a-zA-Z0-9_\-\.]+):(?P<pass>[a-zA-Z0-9_\-\.]+)@)?(?P<host>\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-zA-Z0-9\.\-]+):(?P<port>\d{1,5})",
        )
        .expect("Valid candidate regex");

        // Matches CIDR: e.g. 198.51.100.0/28:8080 or 198.51.100.0/28 8080
        let cidr_regex = Regex::new(
            r"(?i)(?P<cidr>[0-9]{1,3}(?:\.[0-9]{1,3}){3}/\d{1,2}|\[[0-9a-fA-F:]+\]/\d{1,3})[:\s](?P<port>\d{1,5})",
        )
        .expect("Valid CIDR regex");

        Self {
            url_regex,
            cidr_regex,
        }
    }

    /// Extracts proxy candidates from arbitrary unstructured text.
    ///
    /// Automatically expands safe CIDR ranges (up to /16 for IPv4) and drops bogon IPs.
    pub fn extract(&self, text: &str) -> Vec<CandidateProxy> {
        let mut candidates = HashSet::new();

        // 1. Extract CIDR ranges first
        for cap in self.cidr_regex.captures_iter(text) {
            let cidr_str = &cap["cidr"];
            let port_str = &cap["port"];

            if let (Ok(net), Ok(port)) = (IpNet::from_str(cidr_str), port_str.parse::<u16>()) {
                if port > 0 {
                    let _ = self.expand_cidr(net, port, &mut candidates);
                }
            }
        }

        // 2. Extract standard proxy URLs and host:port pairs
        for cap in self.url_regex.captures_iter(text) {
            let host_raw = &cap["host"];
            let port_str = &cap["port"];

            let port = match port_str.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => continue,
            };

            let clean_host = host_raw.trim_matches('[').trim_matches(']');
            let ip: IpAddr = match clean_host.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    // Hostname - we don't resolve during scraping to avoid blocking/slow DNS
                    continue;
                }
            };

            // Filter bogons
            if is_bogon(ip) {
                continue;
            }

            let proto = cap
                .name("proto")
                .and_then(|m| ProxyProto::from_str(m.as_str()).ok());
            let username = cap.name("user").map(|m| m.as_str().to_string());
            let password = cap.name("pass").map(|m| m.as_str().to_string());

            candidates.insert(CandidateProxy {
                addr: SocketAddr::new(ip, port),
                proto,
                username,
                password,
            });
        }

        candidates.into_iter().collect()
    }

    fn expand_cidr(
        &self,
        net: IpNet,
        port: u16,
        out: &mut HashSet<CandidateProxy>,
    ) -> Result<(), ScraperError> {
        match net {
            IpNet::V4(v4) => {
                if v4.prefix_len() < 16 {
                    return Err(ScraperError::CidrTooLarge(MAX_CIDR_HOSTS));
                }
                for host in v4.hosts() {
                    let ip = IpAddr::V4(host);
                    if !is_bogon(ip) {
                        out.insert(CandidateProxy::new(SocketAddr::new(ip, port), None));
                    }
                }
            }
            IpNet::V6(v6) => {
                if v6.prefix_len() < 120 {
                    return Err(ScraperError::CidrTooLarge(MAX_CIDR_HOSTS));
                }
                for host in v6.hosts() {
                    let ip = IpAddr::V6(host);
                    if !is_bogon(ip) {
                        out.insert(CandidateProxy::new(SocketAddr::new(ip, port), None));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_mixed_text() {
        let text = r#"
            socks5://user:pass@8.8.8.8:1080
            http://1.1.1.1:8080
            127.0.0.1:8080
            10.0.0.1:3128
            93.184.216.34:443
            socks4://93.184.216.35:1080
        "#;

        let extractor = CandidateExtractor::new();
        let extracted = extractor.extract(text);

        // 127.0.0.1 and 10.0.0.1 must be dropped by bogon filter
        assert_eq!(extracted.len(), 4);

        let s5 = extracted
            .iter()
            .find(|c| c.addr == "8.8.8.8:1080".parse().unwrap())
            .unwrap();
        assert_eq!(s5.proto, Some(ProxyProto::Socks5));
        assert_eq!(s5.username.as_deref(), Some("user"));
        assert_eq!(s5.password.as_deref(), Some("pass"));
    }
}
