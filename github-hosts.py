# https://github.com/feng2208/github-hosts

# mitmdump -s github-hosts.py -p 8080 

# "patterns": [
#     "example.com",
#     "*.example.com", # all subdomains
#  ],
# "sni": "",
# "address": ("ip", port),
# "verify_host": "", # use to verify server cert

# blackboxprotobuf version: 1.4.0 https://github.com/nccgroup/blackboxprotobuf
# six version: 1.16.0 https://github.com/benjaminp/six

# apple app store region
apple_region = {
    "host": "-buy.itunes.apple.com",
    "address": ("138.2.35.57", 443),
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
    "address": ("138.2.35.57", 443),
}

github_hosts = {
  "mappings": [
    ### github
    {
      "patterns": [
        "github.com",
      ],
      "sni": "octocaptcha.com",
      "address": ("20.27.177.113", 443),
    },
    {
      "patterns": [
        "github.githubassets.com",
      ],
      "sni": "yelp.com",
      "address": ("199.232.240.116", 443),
    },
    {
      "patterns": [
        "*.githubusercontent.com",
      ],
      "sni": "githubusercontent.com",
      "address": ("199.232.176.133", 443),
    },
    ### spotify
    {
      # spotify signup and login
      "patterns": [
        "accounts.spotify.com",
        "www.spotify.com",
      ],
      "address": ("138.2.35.57", 443),
    },
    {
      "patterns": [
        "spclient.wg.spotify.com",
      ],
      "sni": "www.spotify.com",
      "address": ("138.2.35.57", 443),
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
      "address": ("gae2-spclient.spotify.com", 443),
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
      "address": ("0.0.0.1", 443),
    },
    # spotify recaptcha
    {
      "patterns": [
        "www.google.com",
      ],
      "sni": "www.recaptcha.net",
      "address": ("60.72.28.92", 18516),
    },
  ]
}

# spotify vip
changes = {
    'player-license': 'premium',
    'streaming-rules': '',
    'financial-product': 'pr:premium,tc:0',
    'license-acceptance-grace-days': 30,
    'name': 'Spotify Premium',
    'on-demand': 1,
    'ads': 0,
    'catalogue': 'premium',
    'high-bitrate': 1,
    'libspotify': 1,
    'nft-disabled': '1',
    'shuffle': 0,
    'audio-quality': '1',
    'offline': 1,
    'pause-after': 0,
    'can_use_superbird': 1,
    'type': 'premium',
    'com.spotify.madprops.use.ucs.product.state': 1,
}

changes_del = [
    'ad-use-adlogic',
    'ad-catalogues',
]


ssl_verify_hosts: dict = {}


import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls
from mitmproxy import ctx
from mitmproxy.proxy.server_hooks import ServerConnectionHookData
from mitmproxy.addons.tlsconfig import TlsConfig

from OpenSSL import SSL
from OpenSSL.crypto import X509StoreContext
from OpenSSL.crypto import X509StoreContextError
from cryptography import x509

import os
import sys
_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _BASE_DIR + "/lib/")
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException


# spotify ptotobuf
def modify_spotify_body(data, bootstrap=False):
    try:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-xxxxxxxx")
        message, typedef = blackboxprotobuf.decode_message(data)
    except BlackboxProtobufException:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-Error-xxxxxxxx")
        return None
        
    if bootstrap:
        configs = message['2']['1']['1']['1']['3']['1']
    else:
        configs = message['1']['3']['1']

    if isinstance(configs, list):
        for config in configs:
            attr_key = config['1']
            value_key = list(config['2'].keys())[0]
            if attr_key in list(changes.keys()):
                config['2'][value_key] = changes[attr_key]
            elif attr_key in changes_del:
                configs.remove(config)

        if bootstrap:
            message['2']['1']['1']['1']['3']['1'] = configs
        else:
            message['1']['3']['1'] = configs

        try:
            logging.info(f"xxxxxxxx-spotify-protobuf-encode-xxxxxxxx")
            data = blackboxprotobuf.encode_message(message, typedef)
            return data
        except BlackboxProtobufException:
            logging.info(f"xxxxxxxx-spotify-protobuf-encode-Error-xxxxxxxx")
    return None


def verify_callback(conn, cert, error_n, error_depth, return_code) -> bool:
    ctx = conn.get_context()
    store = ctx.get_cert_store()
    cert_chain = conn.get_peer_cert_chain()
    host = conn.get_servername().decode("utf-8")

    try:
        X509StoreContext(store, cert, cert_chain).verify_certificate()
    except X509StoreContextError:
        return False

    if cert_chain[0].get_serial_number() == cert.get_serial_number():
        crypto_cert = cert.to_cryptography()
        ext = crypto_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if ssl_verify_hosts[host] not in ext.value.get_values_for_type(x509.DNSName):
            return False
    return True


@dataclass
class Mapping:
    sni: str
    address: tuple

class GithubHosts(TlsConfig):
    # configurations for regular ("example.com") mappings:
    host_mappings: dict[str, Mapping]

    # Configurations for star ("*.example.com") mappings:
    star_mappings: dict[str, Mapping]

    github_hosts_loaded: bool

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
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

    def running(self):
        if not self.github_hosts_loaded:
            self._load_github_hosts()
            self.github_hosts_loaded = True

    def server_connect(self, data: ServerConnectionHookData) -> None:
        host = data.server.address[0]
        if host in spotify_geo['hosts']:
            msg = f"{host} {spotify_geo['address']}"
            logging.info(f"xxxxxxxx-spotify-geo-server: {msg}")
            data.server.address = spotify_geo['address']

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        host = data.context.client.sni
        if host is None:
            return

        # apple app store region
        if host.endswith(apple_region['host']):
            data.context.server.address = apple_region['address']
            logging.info(f"xxxxxxxx-apple-region-host: {host}")
            logging.info(f"xxxxxxxx-apple-region-address: {apple_region['address']}")
            return

        mapping = self._get_sni(host)
        if mapping is not None:
            logging.info(f"xxxxxxxx-tls-server-host: {host}")
            if mapping.sni is not None:
                data.ignore_connection = False
                data.context.server.sni = mapping.sni
                logging.info(f"xxxxxxxx-tls-server-sni: {mapping.sni}")
            if mapping.address is not None:
                data.context.server.address = mapping.address
                logging.info(f"xxxxxxxx-tls-server-address: {mapping.address}")

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        super().tls_start_server(tls_start)
        if tls_start.conn.sni in list(ssl_verify_hosts.keys()):
            tls_start.ssl_conn.set_verify(SSL.VERIFY_PEER, verify_callback)

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
        elif req_host_header == "spclient.wg.spotify.com":
            # spotify ads and trackers
            if (req_path.startswith("/ads/") or
                    req_path.startswith("/ad-logic/") or
                    req_path.startswith("/desktop-update/") or
                    req_path.startswith("/gabo-receiver-service/")):
                flow.response = Response.make(503)
            # spotify protobuf
            if (req_path.startswith("/user-customization-service/v1/customize")
                    or req_path.startswith("/bootstrap/v1/bootstrap")):
                if 'if-none-match' in flow.request.headers:
                    del flow.request.headers['if-none-match']

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True
        req_path = flow.request.path
        if (req_path.startswith("/user-customization-service/v1/customize")
                or req_path.startswith("/bootstrap/v1/bootstrap")):
            flow.response.stream = False

    def response(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        if flow.request.host_header == "spclient.wg.spotify.com":
            if (req_path.startswith("/user-customization-service/v1/customize")
                    or req_path.startswith("/bootstrap/v1/bootstrap")):
                if flow.response.status_code != 200:
                    logging.info(f"xxxxxxxx-spotify-protobuf-status-code-not200-xxxxxxxx")
                    return
                if not isinstance(flow.response.content, bytes):
                    return
                if req_path.startswith("/bootstrap/v1/bootstrap"):
                    logging.info(f"xxxxxxxx-spotify-protobuf-bootstrap-xxxxxxxx")
                    data = modify_spotify_body(flow.response.content, bootstrap=True)
                else:
                    logging.info(f"xxxxxxxx-spotify-protobuf-customize-xxxxxxxx")
                    data = modify_spotify_body(flow.response.content)
                if data is not None:
                    flow.response.content = data

    def _load_github_hosts(self) -> None:
        host_mappings: dict[str, Mapping] = {}
        star_mappings: dict[str, Mapping] = {}

        for mapping in github_hosts["mappings"]:
            address = mapping.get("address")
            sni = mapping.get("sni")
            verify_host = mapping.get("verify_host")
            if verify_host is not None and sni is not None:
                ssl_verify_hosts[sni] = verify_host

            item = Mapping(
                        sni=sni,
                        address=address,
                   )
            for pattern in mapping["patterns"]:
                if pattern.startswith("*."):
                    star_mappings[pattern[2:]] = item
                else:
                    host_mappings[pattern] = item

        self.host_mappings = host_mappings
        self.star_mappings = star_mappings

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
