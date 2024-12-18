# https://github.com/feng2208/github-hosts

# mitmdump -s src/github-hosts.py -p 8180 
# deps:
#   blackboxprotobuf v1.4.0 https://github.com/nccgroup/blackboxprotobuf
#   six v1.16.0 https://github.com/benjaminp/six


import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls
from mitmproxy.addons.tlsconfig import TlsConfig

from OpenSSL import SSL
from OpenSSL.crypto import X509StoreContext
from OpenSSL.crypto import X509StoreContextError
from cryptography import x509

import os
import sys
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SRC_DIR + "/lib/")
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException

from pathlib import Path
from ruamel.yaml import YAML


CONFIG_FILE = SRC_DIR + "/config.yaml"
SSL_VERIFY_HOSTS: dict = {}

SPOTS = {
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

SPOTS_DEL = [
    'ad-use-adlogic',
    'ad-catalogues',
]


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

    changed = False
    if isinstance(configs, list):
        for config in configs:
            # config: {'1': 'attr_key', '2': {'value_key': 'value'}}
            # SPOTS: {'attr_key': 'value'}
            if not isinstance(config, dict):
                continue
            if '1' not in config or '2' not in config:
                continue
            if not isinstance(config['2'], dict):
                continue

            attr_key = config['1']
            value_key = list(config['2'].keys())[0]
            if attr_key in SPOTS:
                config['2'][value_key] = SPOTS[attr_key]
                changed = True
            elif attr_key in SPOTS_DEL:
                configs.remove(config)
                changed = True

        if bootstrap:
            message['2']['1']['1']['1']['3']['1'] = configs
        else:
            message['1']['3']['1'] = configs

        if changed:
            logging.info(f"xxxxxxxx-spotify-protobuf-changed-xxxxxxxx")
            try:
                logging.info(f"xxxxxxxx-spotify-protobuf-encode-xxxxxxxx")
                data = blackboxprotobuf.encode_message(message, typedef)
                return data
            except BlackboxProtobufException:
                logging.info(f"xxxxxxxx-spotify-protobuf-encode-Error-xxxxxxxx")

    if not changed:
        logging.info(f"xxxxxxxx-spotify-protobuf-not-changed-xxxxxxxx")
        logging.info(f"xxxxxxxx-spotify-protobuf-need-to-update-code-xxxxxxxx")

    return None


def verify_callback(conn, cert, error_n, error_depth, return_code) -> bool:
    ctx = conn.get_context()
    store = ctx.get_cert_store()
    cert_chain = conn.get_peer_cert_chain()

    try:
        X509StoreContext(store, cert, cert_chain).verify_certificate()
    except X509StoreContextError:
        return False

    if cert_chain[0].get_serial_number() == cert.get_serial_number():
        crypto_cert = cert.to_cryptography()
        ext = crypto_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if SSL_VERIFY_HOSTS[conn.verify_key] not in ext.value.get_values_for_type(x509.DNSName):
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
    spotify_auth: bool
    yaml_config: dict

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
        self.github_hosts_loaded = False
        self.spotify_auth = False
        self.yaml_config = {}

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
            yaml = YAML(typ='safe')
            self.yaml_config = yaml.load(Path(CONFIG_FILE))
            self._load_github_hosts()
            self.github_hosts_loaded = True

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        host = data.context.client.sni
        if host in self.yaml_config['spotify_hosts']:
            _addr = self.yaml_config['spotify_address']
            _spot_addr = (_addr.split(':')[0], int(_addr.split(':')[1]))
            if host == "spclient.wg.spotify.com":
                data.ignore_connection = False
                if self.spotify_auth:
                    data.context.server.address = _spot_addr
            else:
                data.context.server.address = _spot_addr
                self.spotify_auth = True
            logging.info(f"xxxxxxxx-tls-server-host: {host}")
            logging.info(f"xxxxxxxx-tls-server-address: {data.context.server.address}")
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
        if tls_start.conn.sni in SSL_VERIFY_HOSTS:
            tls_start.ssl_conn.set_tlsext_host_name(b"")
            tls_start.ssl_conn.verify_key = tls_start.conn.sni
            tls_start.ssl_conn.set_verify(SSL.VERIFY_PEER, verify_callback)

    def requestheaders(self, flow: HTTPFlow) -> None:
        flow.request.stream = True
        req_path = flow.request.path
        req_host = flow.request.host_header          
        # spotify recaptcha
        if req_host == "www.google.com":
            flow.request.host = "www.recaptcha.net"
                
        elif req_host == "spclient.wg.spotify.com":
            # spotify ads and trackers
            if (req_path.startswith("/ads/")
                    or req_path.startswith("/ad-logic/")
                    or req_path.startswith("/desktop-update/")
                    or req_path.startswith("/gabo-receiver-service/")):
                flow.request.stream = False
                flow.response = Response.make(503)
            # spotify protobuf
            elif self._spclient(flow):
                if 'if-none-match' in flow.request.headers:
                    del flow.request.headers['if-none-match']

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True
        if (self._spclient(flow)
                or flow.request.host_header == "www.recaptcha.net"):
            flow.response.stream = False

    def response(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        req_host = flow.request.host_header
        if (req_host == "www.recaptcha.net"
                and req_path.startswith("/recaptcha/")):
            replacements = [
                ("www.gstatic.cn", "www.gstatic.com"),
                ("www.recaptcha.net", "www.google.com"),
            ]
            for old, new in replacements:
                flow.response.text = flow.response.text.replace(old, new)
        
        elif self._spclient(flow):
            if flow.response.status_code != 200:
                logging.info(f"xxxxxxxx-spotify-protobuf-status-code-not-200-xxxxxxxx")
                return
            if not isinstance(flow.response.content, bytes):
                logging.info(f"xxxxxxxx-spotify-protobuf-not-bytes-xxxxxxxx")
                return
            if req_path.startswith("/bootstrap/v1/bootstrap"):
                logging.info(f"xxxxxxxx-spotify-protobuf-bootstrap-xxxxxxxx")
                data = modify_spotify_body(flow.response.content, bootstrap=True)
            else:
                logging.info(f"xxxxxxxx-spotify-protobuf-customize-xxxxxxxx")
                data = modify_spotify_body(flow.response.content)
            if data is not None:
                flow.response.content = data
                    
    def _spclient(self, flow: HTTPFlow) -> bool:
        req_path = flow.request.path
        req_host = flow.request.host_header
        if req_host == "spclient.wg.spotify.com":
            if (req_path.startswith("/user-customization-service/v1/customize")
                    or req_path.startswith("/bootstrap/v1/bootstrap")):
                return True
        return False
        
    def _load_github_hosts(self) -> None:
        host_mappings: dict[str, Mapping] = {}
        star_mappings: dict[str, Mapping] = {}

        for mapping in self.yaml_config["mappings"]:
            address = mapping.get("address")
            sni = mapping.get("sni")
            verify_host = mapping.get("verify_host")
            if verify_host is not None and sni is not None:
                SSL_VERIFY_HOSTS[sni] = verify_host
            if address is not None:
                address = (address.split(':')[0], int(address.split(':')[1]))

            item = Mapping(
                        sni=sni,
                        address=address,
                   )
            for host in mapping["hosts"]:
                if host.startswith("*."):
                    star_mappings[host[2:]] = item
                else:
                    host_mappings[host] = item

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
            super_domain = host[(index + 1):]
            mapping = self.star_mappings.get(super_domain)
            if mapping is not None:
                return mapping
            index += 1

        return None


addons = [GithubHosts()]
