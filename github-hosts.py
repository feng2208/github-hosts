# ./mitmdump -s ./github-hosts.py -p 8080
# ./mitmdump -s ./github-hosts.py -p 8080 --set dianxin=true
# https://github.com/feng2208/github-hosts

### 'xxx_dx' overwrite 'xxx' when '--set dianxian=true'
# sni, sni_dx
# ip, ip_dx
# port, port_dx
# ssl_verify, ssl_verify_dx: default to "yes"

github_hosts = {
  "mappings": [
    { # github
      "patterns": [
        "github.com",
      ],
      "sni": "octocaptcha.com",
    },
    {
      "patterns": [
        "*.githubusercontent.com",
        "github.githubassets.com",
      ],
      "sni": "github.githubassets.com",
      "sni_dx": "www.yelp.com",
      "ip_dx": "151.101.40.116",
    },
  ]
}


import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow
from mitmproxy import tls
from mitmproxy import ctx

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
            name="dianxin",
            typespec=bool,
            default=False,
            help="set dianxin network",
        )

    def running(self):
        if not self.github_hosts_loaded:
            self._load_github_hosts()
            self.github_hosts_loaded = True

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True

        _host = data.context.server.address[0]
        _port = data.context.server.address[1]
        logging.info(f"tls-server-host: {_host}")
        mapping = self._get_sni(_host)
        if mapping is not None:
            if mapping.sni is not None:
                data.ignore_connection = False
                data.context.server.sni = mapping.sni
                _host = mapping.sni
            if mapping.ip is not None:
                _host = mapping.ip
            if mapping.port is not None:
                _port = mapping.port
            data.context.server.address = (_host, _port)
            logging.info(f"tls-server-sni: {data.context.server.sni}")
            logging.info(f"tls-server-address: {data.context.server.address}")

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        super().tls_start_server(tls_start)
        if tls_start.conn.sni in self.ssl_no_verify_hosts:
            logging.info(f"tls-server-no-verify: {tls_start.conn.sni}")
            tls_start.ssl_conn.set_verify(SSL.VERIFY_NONE)

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True

    def _load_github_hosts(self) -> None:
        host_mappings: dict[str, Mapping] = {}
        star_mappings: dict[str, Mapping] = {}
        ssl_no_verify_hosts: list[str] = []

        for mapping in github_hosts["mappings"]:
            _sni = mapping.get("sni")
            _ip = mapping.get("ip")
            _port = mapping.get("port")
            _ssl_verify = mapping.get("ssl_verify", "yes")
            if ctx.options.dianxin:
                if mapping.get("sni_dx") is not None:
                    _sni = mapping.get("sni_dx")
                if mapping.get("ip_dx") is not None:
                    _ip = mapping.get("ip_dx")
                if mapping.get("port_dx") is not None:
                    _port = mapping.get("port_dx")
                if mapping.get("ssl_verify_dx") is not None:
                    _ssl_verify = mapping.get("ssl_verify_dx", "yes")

            if _ssl_verify == "no" and _sni is not None:
                ssl_no_verify_hosts.append(_sni)

            item = Mapping(
                        sni=_sni,
                        ip=_ip,
                        port=_port
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
