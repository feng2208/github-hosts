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
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

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
import re

CONFIG_FILE = SRC_DIR + "/config.yaml"

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
    if return_code == 1:
        return True

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
        dns_names = ext.value.get_values_for_type(x509.DNSName)
        if conn.verify_host1 not in dns_names and conn.verify_host2 not in dns_names:
            n_host1 = re.sub(r'^\w+\.', '*.', conn.verify_host1)
            n_host2 = re.sub(r'^\w+\.', '*.', conn.verify_host2)
            if n_host1 not in dns_names and n_host2 not in dns_names:
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

    tcp_hosts: list[str]

    github_hosts_loaded: bool
    spotify_auth: bool
    yaml_config: dict

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
        self.tcp_hosts = []
        self.github_hosts_loaded = False
        self.spotify_auth = False
        self.yaml_config = {}

    def load(self, loader: Loader) -> None:
        if not self.github_hosts_loaded:
            yaml = YAML(typ='safe')
            self.yaml_config = yaml.load(Path(CONFIG_FILE))
            self._load_github_hosts()
            self.github_hosts_loaded = True

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
            name="tcp_hosts",
            typespec=list,
            default=self.tcp_hosts,
            help="Generic TCP SSL proxy mode for all hosts that match the pattern",
        )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        host = data.context.client.sni
        if host in self.yaml_config['spotify_hosts']:
            _spot_addr = self.yaml_config['spotify_address']
            spot_addr = (_spot_addr.split(':')[0], int(_spot_addr.split(':')[1]))
            if host == "spclient.wg.spotify.com":
                data.ignore_connection = False
                if self.spotify_auth:
                    data.context.server.address = spot_addr
            else:
                data.context.server.address = spot_addr
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

        else:
            s_host = data.context.server.address[0]
            s_port = data.context.server.address[1]
            c_port = data.context.client.peername[1]
            logging.info(f"{c_port} {s_host}:{s_port}")

    def tls_start_server(self, tls_start: tls.TlsData) -> None:
        super().tls_start_server(tls_start)
        tls_start.ssl_conn.verify_host1 = tls_start.conn.sni
        tls_start.ssl_conn.verify_host2 = tls_start.context.client.sni
        if tls_start.conn.sni.startswith("_"):
            tls_start.ssl_conn.set_tlsext_host_name(b"")
            tls_start.ssl_conn.verify_host1 = tls_start.conn.sni[1:]
        tls_start.ssl_conn.set_verify(SSL.VERIFY_PEER, verify_callback)

    def server_connect(self, data: ServerConnectionHookData) -> None:
        _host = data.server.address[0]
        if self.spotify_auth and _host in self.yaml_config['spotify_ap']:
            host = self.yaml_config['spotify_ap_address'].split(':')[0]
            port = int(self.yaml_config['spotify_ap_address'].split(':')[1])
            data.server.address = (host, port)
            logging.info(f"xxxxxxxx-spotify-ap: {_host} {data.server.address}")

    def requestheaders(self, flow: HTTPFlow) -> None:
        flow.request.stream = True
        req_path = flow.request.path
        req_host = flow.request.host_header          
        if req_host == "spclient.wg.spotify.com":
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
            elif (req_path.startswith("/artistview/v1/artist")):
                flow.request.path = flow.request.path.replace('platform=iphone', 'platform=ipad')

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True
        if self._spclient(flow):
            flow.response.stream = False

    def response(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        req_host = flow.request.host_header
        if self._spclient(flow):
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
        tcp_hosts: list[str] = []

        for mapping in self.yaml_config["mappings"]:
            address = mapping.get("address")
            sni = mapping.get("sni")
            if address is not None:
                address = (address.split(':')[0], int(address.split(':')[1]))

            item = Mapping(
                        sni=sni,
                        address=address,
                   )
            for host in mapping["hosts"]:
                if host.startswith("*."):
                    star_mappings[host[2:]] = item
                    if sni is not None:
                        tcp_hosts.append(host[1:].replace('.', r'\.'))
                else:
                    host_mappings[host] = item
                    if sni is not None:
                        tcp_hosts.append(host.replace('.', r'\.'))

        self.host_mappings = host_mappings
        self.star_mappings = star_mappings
        self.tcp_hosts = tcp_hosts

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
