use looker_protocol::ProxyProto;

#[derive(Debug, Clone)]
pub struct ProxySource {
    pub name: &'static str,
    pub url: &'static str,
    pub default_proto: Option<ProxyProto>,
}

/// Complete verified 52 public proxy sources from monosans/proxy-scraper-checker.
pub static DEFAULT_SOURCES: &[ProxySource] = &[
    // ============================================================
    // HTTP Feeds (21 endpoints)
    // ============================================================
    ProxySource {
        name: "proxyscrape-http-v2",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "proxyscrape-http-v3",
        url: "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=protocolipport&format=text",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "proxyspace-https",
        url: "https://proxyspace.pro/https.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "6yyn-http",
        url: "https://raw.githubusercontent.com/6yyn/free-proxy-list/refs/heads/main/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "bes-js-proxies",
        url: "https://raw.githubusercontent.com/Bes-js/public-proxy-list/refs/heads/main/proxies.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "edt-pages-http",
        url: "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/refs/heads/main/data/http.json",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "tianndev-http",
        url: "https://raw.githubusercontent.com/Tianndev/free-proxy/refs/heads/main/proxy/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "anutmagang-all",
        url: "https://raw.githubusercontent.com/anutmagang/Free-HighQuality-Proxy-Socks/refs/heads/main/results/all.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "databay-http",
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "dinoz0rg-http",
        url: "https://raw.githubusercontent.com/dinoz0rg/proxy-list/refs/heads/main/checked_proxies/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "hproxy-http",
        url: "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/refs/heads/main/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "hproxy-https",
        url: "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/refs/heads/main/https.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "maximilianfeix-https",
        url: "https://raw.githubusercontent.com/maximilianfeix/free-proxy-list/refs/heads/main/https.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "mmpx12-http",
        url: "https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "proxmint-http",
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/refs/heads/main/proxies/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "stormsia-http",
        url: "https://raw.githubusercontent.com/stormsia/proxy-list/refs/heads/main/http.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "vmheaven-https",
        url: "https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/refs/heads/main/https.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "watchttvv-http",
        url: "https://raw.githubusercontent.com/watchttvv/free-proxy-list/refs/heads/main/proxy.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "xyzs996-http",
        url: "https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/refs/heads/main/proxies/protocols/http/data.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "xyzs996-https",
        url: "https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/refs/heads/main/proxies/protocols/https/data.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },
    ProxySource {
        name: "zloi-user-connect",
        url: "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/main/connect.txt",
        default_proto: Some(ProxyProto::HttpConnect),
    },

    // ============================================================
    // SOCKS4 Feeds (8 endpoints)
    // ============================================================
    ProxySource {
        name: "proxyscrape-socks4",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "anonym0uswork-socks4",
        url: "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/refs/heads/main/proxy_files/socks4_proxies.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "databay-socks4",
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "hproxy-socks4",
        url: "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/refs/heads/main/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "proxio-socks4",
        url: "https://raw.githubusercontent.com/proxio-io/proxy-list/refs/heads/main/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "proxmint-socks4",
        url: "https://raw.githubusercontent.com/proxmint/free-proxy-list/refs/heads/main/proxies/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "sunny9577-socks4",
        url: "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks4_proxies.txt",
        default_proto: Some(ProxyProto::Socks4),
    },
    ProxySource {
        name: "vmheaven-socks4",
        url: "https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/refs/heads/main/socks4.txt",
        default_proto: Some(ProxyProto::Socks4),
    },

    // ============================================================
    // SOCKS5 Feeds (23 endpoints)
    // ============================================================
    ProxySource {
        name: "proxyscrape-socks5",
        url: "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "edt-pages-socks5",
        url: "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/refs/heads/main/data/socks5.json",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "proxyscrape-socks5-data",
        url: "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "tianndev-socks5",
        url: "https://raw.githubusercontent.com/Tianndev/free-proxy/refs/heads/main/proxy/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "tuanminpay-socks5",
        url: "https://raw.githubusercontent.com/TuanMinPay/live-proxy/refs/heads/master/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "vpslab-socks5",
        url: "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/socks5_all.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "databay-socks5",
        url: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "dinoz0rg-socks5",
        url: "https://raw.githubusercontent.com/dinoz0rg/proxy-list/refs/heads/main/checked_proxies/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "dpangestuw-socks5",
        url: "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "elliottophellia-socks5",
        url: "https://raw.githubusercontent.com/elliottophellia/proxylist/refs/heads/master/results/socks5/global/socks5_checked.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "hproxy-socks5",
        url: "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "iplocate-socks5",
        url: "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "litportnet-socks5",
        url: "https://raw.githubusercontent.com/litportnet/free-proxy-list/refs/heads/main/proxies/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "maximilianfeix-socks5",
        url: "https://raw.githubusercontent.com/maximilianfeix/free-proxy-list/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "nguyenduytan-socks5",
        url: "https://raw.githubusercontent.com/nguyenduytan/NDT-Proxy-Scraper/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "proxifly-socks5",
        url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "proxy-free-socks5",
        url: "https://raw.githubusercontent.com/proxy-free/free-proxy-list/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "stormsia-socks5",
        url: "https://raw.githubusercontent.com/stormsia/proxy-list/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "sunny9577-socks5",
        url: "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "vmheaven-socks5",
        url: "https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "wyattowalsh-socks5",
        url: "https://raw.githubusercontent.com/wyattowalsh/proxywhirl/refs/heads/main/web/public/proxy-lists/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "z3a4-socks5",
        url: "https://raw.githubusercontent.com/z3a4/free-proxy-list/refs/heads/main/proxies/unchecked/socks5-proxies.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
    ProxySource {
        name: "zloi-user-socks5",
        url: "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/main/socks5.txt",
        default_proto: Some(ProxyProto::Socks5),
    },
];
