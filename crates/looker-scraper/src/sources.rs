use looker_protocol::ProxyProto;

#[derive(Debug, Clone)]
pub struct ProxySource {
    pub name: &'static str,
    pub url: &'static str,
    pub default_proto: Option<ProxyProto>,
}

/// Curated high-availability public proxy sources.
pub static DEFAULT_SOURCES: &[ProxySource] = &[
    // Monosans curated GitHub lists
    ProxySource {
        name: "monosans-http",
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "monosans-socks4",
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "monosans-socks5",
        url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    // TheSpeedX proxy lists
    ProxySource {
        name: "thespeedx-http",
        url: "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "thespeedx-socks4",
        url: "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "thespeedx-socks5",
        url: "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    // ProxyScrape API feeds
    ProxySource {
        name: "proxyscrape-http",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "proxyscrape-socks4",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "proxyscrape-socks5",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
        default_proto: Some(ProxyProto::Socks5),
    },
    // Proxifly aggregated list
    ProxySource {
        name: "proxifly-all",
        url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        default_proto: None,
    },
];
