# https://github.com/feng2208/github-hosts
# mitmdump -s src/github-hosts.py --set flow_detail=0 -p 8180


import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy import tls
from mitmproxy.addons.tlsconfig import TlsConfig

from OpenSSL import SSL
from OpenSSL.crypto import X509StoreContext
from OpenSSL.crypto import X509StoreContextError
from cryptography import x509

from pathlib import Path
from ruamel.yaml import YAML
import re

import os
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = SRC_DIR + "/config.yaml"


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
        if conn.conn_sni not in dns_names and re.sub(r'^\w+\.', '*.', conn.conn_sni) not in dns_names:
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
    yaml_config: dict

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
        self.tcp_hosts = []
        self.github_hosts_loaded = False
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
        tls_start.ssl_conn.conn_sni = tls_start.conn.sni
        if tls_start.conn.sni.startswith("_"):
            tls_start.ssl_conn.set_tlsext_host_name(b"")
            tls_start.ssl_conn.conn_sni = tls_start.conn.sni[1:]
        tls_start.ssl_conn.set_verify(SSL.VERIFY_PEER, verify_callback)
        
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
