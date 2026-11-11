use std::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        TargetAddr::Ip(addr)
    }

    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        TargetAddr::Domain(domain.into(), port)
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.ip().to_string(),
            TargetAddr::Domain(domain, _) => domain.clone(),
        }
    }

    pub fn to_authority(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => {
                if addr.is_ipv6() {
                    format!("[{}]:{}", addr.ip(), addr.port())
                } else {
                    format!("{}:{}", addr.ip(), addr.port())
                }
            }
            TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_authority())
    }
}

impl TryFrom<&str> for TargetAddr {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(TargetAddr::Ip(addr));
        }

        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port = parts[0]
                .parse::<u16>()
                .map_err(|_| format!("Invalid port in authority: {}", s))?;
            let mut host = parts[1];
            if host.starts_with('[') && host.ends_with(']') {
                host = &host[1..host.len() - 1];
            }
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(TargetAddr::Ip(SocketAddr::new(ip, port)));
            }
            return Ok(TargetAddr::Domain(host.to_string(), port));
        }

        Err(format!("Invalid target address format: {}", s))
    }
}
