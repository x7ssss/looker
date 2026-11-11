use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProxyProto {
    #[cfg_attr(feature = "serde", serde(rename = "socks5"))]
    Socks5,
    #[cfg_attr(feature = "serde", serde(rename = "socks4"))]
    Socks4,
    #[cfg_attr(feature = "serde", serde(rename = "http"))]
    HttpConnect,
}

impl ProxyProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyProto::Socks5 => "socks5",
            ProxyProto::Socks4 => "socks4",
            ProxyProto::HttpConnect => "http",
        }
    }
}

impl fmt::Display for ProxyProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProxyProto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" => Ok(ProxyProto::Socks5),
            "socks4" | "socks4a" => Ok(ProxyProto::Socks4),
            "http" | "https" | "connect" => Ok(ProxyProto::HttpConnect),
            other => Err(format!("Unknown proxy protocol: {}", other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub proto: ProxyProto,
    pub latency: Duration,
    pub success: bool,
    pub error: Option<String>,
}
