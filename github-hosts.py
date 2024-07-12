# https://github.com/feng2208/github-hosts

# mitmdump -s github-hosts.py -p 8080 
# --set spotify_auth
# --set dianxin

# "patterns": [
#     "example.com",
#     "*.example.com", # all subdomains
#  ],
# "sni": "",
# "ip": "",
# "port": ,
# "ssl_verify": "", # yes or no, default yes
# "ssl_verify": "", # yes or no, default yes
# xxx_dx: for telecom network


# apple app store region
apple_region = {
    "host": "-buy.itunes.apple.com",
    "ip": "138.2.35.57",
    "port": 4072
}

# spotify signup and login
spotify_auth = {
    "sni": "www.spotify.com",
    "ip": "35.196.128.213",
    "port": 40129
}

spotify_geo = {
    # spotify client access point: https://apresolve.spotify.com/
    "hosts": [
        "ap-gae2.spotify.com",
        "ap-guc3.spotify.com",
        "ap-gue1.spotify.com",
        "ap-gew1.spotify.com",
        "ap-gew4.spotify.com",
    ],
    "ip": "138.2.35.57",
    "port": 4071
}

spotify_audio = [
    "audio-fa.scdn.co",
    "audio-ak-spotify-com.akamaized.net",
]

github_hosts = {
  "mappings": [
    ### github
    {
      "patterns": [
        "github.com",
      ],
      "sni": "octocaptcha.com",
      "ip": "20.27.177.113",
    },
    {
      "patterns": [
        "*.githubusercontent.com",
        "github.githubassets.com",
      ],
      "sni": "yelp.com",
      "ip": "151.101.232.116",
      "ip_dx": "151.101.40.116",
    },
    ### spotify
    {
      # spotify signup and login
      "patterns": [
        "accounts.spotify.com",
        "www.spotify.com",
        "spclient.wg.spotify.com",
      ],
      "sni": spotify_auth["sni"],
      "ip": "gae2-spclient.spotify.com",
    },
    {
      "patterns": [
        "spotify.com",
        "clienttoken.spotify.com",
        "apresolve.spotify.com",
        "login5.spotify.com",
        "api-partner.spotify.com",
        "challenge.spotify.com",
        "api.spotify.com",
      ],
      "ip": "gae2-spclient.spotify.com",
    },
    # spotify ads and trackers
    {
      "patterns": [
        "*.ingest.sentry.io",
        "bloodhound.spotify.com",
        "*.doubleclick.net",
        "*.adsrvr.org",
        "*.googlesyndication.com",
        "adeventtrackermonitoring.spotify.com",
        "video-akpcw-cdn-spotify-com.akamaized.net",
        "video-fa.scdn.co",
        "*.litix.io",
        "*.pix.pub",
        "relaycdn.anchor.fm",
        "*.rubiconproject.com",
        "pixel.spotify.com",
        "pixel-static.spotify.com",
      ],
      "ip": "0.0.0.0",
    },
    # spotify recaptcha
    {
      "patterns": [
        "www.google.com",
      ],
      "sni": "www.recaptcha.net",
      "ip": "60.72.28.92",
      "port": 18516,
    },
  ]
}

import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls
from mitmproxy import ctx
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from OpenSSL import SSL
from mitmproxy.addons.tlsconfig import TlsConfig

@dataclass
class Mapping:
    sni: str
    ip: str
    port: int


class GithubHosts(TlsConfig):
    # configurations for regular ("example.com") mappings:
    host_mappings: dict[str, Mapping]

    # Configurations for star ("*.example.com") mappings:
    star_mappings: dict[str, Mapping]

    ssl_no_verify_hosts: list[str]
    github_hosts_loaded: bool

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
        self.ssl_no_verify_hosts = []
        self.github_hosts_loaded = False

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="connection_strategy",
            typespec=str,
            default="lazy",
            help="set connection strategy to lazy",
        )
        loader.add_option(
            name="showhost",
            typespec=bool,
            default=True,
            help="Use the Host header to construct URLs for display",
        )
        loader.add_option(
            name="dianxin",
            typespec=bool,
            default=False,
            help="set telecom network",
        )
        loader.add_option(
            name="spotify_auth",
            typespec=bool,
            default=False,
            help="spotify auth",
        )

    def running(self):
        if not self.github_hosts_loaded:
            self._load_github_hosts()
            self.github_hosts_loaded = True

    def server_connect(self, data: ServerConnectionHookData) -> None:
        # http mode
        if "regular" not in ctx.options.mode:
            return

        host = data.server.address[0]
        if host in spotify_geo['hosts']:
            msg = f"{host} ({spotify_geo['ip']}:{spotify_geo['port']})"
            logging.info(f"xxxxxxxx-spotify-geo-server: {msg}")
            data.server.address = (spotify_geo['ip'], spotify_geo['port'])

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        host = data.context.client.sni
        port = data.context.server.address[1]
        if host is None:
            return
        logging.info(f"xxxxxxxx-tls-server-host: {host}")

        # spotify
        if ctx.options.spotify_auth and host in spotify_audio:
            host = "0.0.0.0"
            data.context.server.address = (host, port)
            logging.error("请勿使用参数--set spotify_auth")
            return

        # apple app store region
        if host.endswith(apple_region['host']):
            host = apple_region["ip"]
            port = apple_region["port"]
            data.context.server.address = (host, port)
            logging.info(f"xxxxxxxx-apple-region-address: ({host}:{port})")
            return

        mapping = self._get_sni(host)
        if mapping is not None:
            if mapping.sni is not None:
                data.ignore_connection = False
                data.context.server.sni = mapping.sni
                host = mapping.sni
            if mapping.ip is not None:
                host = mapping.ip
            if mapping.port is not None:
                port = mapping.port
            # spotify signup and login
            if ctx.options.spotify_auth and spotify_auth["sni"] == mapping.sni:
                host = spotify_auth["ip"]
                port = spotify_auth["port"]
            logging.info(f"xxxxxxxx-tls-server-sni: {data.context.server.sni}")
            logging.info(f"xxxxxxxx-tls-server-address: ({host}:{port})")
            if data.ignore_connection:
                logging.info("xxxxxxxx-connection: forward")

        data.context.server.address = (host, port)

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        super().tls_start_server(tls_start)
        if tls_start.conn.sni in self.ssl_no_verify_hosts:
            logging.info(f"xxxxxxxx-tls-server-no-verify: {tls_start.conn.sni}")
            tls_start.ssl_conn.set_verify(SSL.VERIFY_NONE)

    def requestheaders(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        req_host_header = flow.request.host_header
        if req_host_header is None:
            return

        # spotify recaptcha
        if req_host_header == "www.google.com":
            if not (req_path.startswith("/recaptcha/") or
                    req_path.startswith("/js/")):
                flow.response = Response.make(404)
        # spotify ads and trackers
        elif req_host_header == "spclient.wg.spotify.com":
            if (req_path.startswith("/ads/") or
                    req_path.startswith("/ad-logic/") or
                    req_path.startswith("/desktop-update/") or
                    req_path.startswith("/gabo-receiver-service/")):
                flow.response = Response.make(503)

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True

    def _load_github_hosts(self) -> None:
        host_mappings: dict[str, Mapping] = {}
        star_mappings: dict[str, Mapping] = {}
        ssl_no_verify_hosts: list[str] = []

        for mapping in github_hosts["mappings"]:
            sni = mapping.get("sni")
            ip = mapping.get("ip")
            port = mapping.get("port")
            ssl_verify = mapping.get("ssl_verify", "yes")
            if ctx.options.dianxin:
                if mapping.get("sni_dx") is not None:
                    sni = mapping.get("sni_dx")
                if mapping.get("ip_dx") is not None:
                    ip = mapping.get("ip_dx")
                if mapping.get("port_dx") is not None:
                    port = mapping.get("port_dx")
                if mapping.get("ssl_verify_dx") is not None:
                    ssl_verify = mapping.get("ssl_verify_dx", "yes")

            if ssl_verify == "no" and sni is not None:
                ssl_no_verify_hosts.append(sni)

            item = Mapping(
                        sni=sni,
                        ip=ip,
                        port=port
                   )
            for pattern in mapping["patterns"]:
                if pattern.startswith("*."):
                    star_mappings[pattern[2:]] = item
                else:
                    host_mappings[pattern] = item

        self.host_mappings = host_mappings
        self.star_mappings = star_mappings
        self.ssl_no_verify_hosts = ssl_no_verify_hosts

    def _get_sni(self, host: str) -> Mapping | None:
        mapping = self.host_mappings.get(host)
        if mapping is not None:
            return mapping

        index = 0
        while True:
            index = host.find(".", index)
            if index == -1:
                break
            super_domain = host[(index + 1) :]
            mapping = self.star_mappings.get(super_domain)
            if mapping is not None:
                return mapping
            index += 1

        return None


addons = [GithubHosts()]
