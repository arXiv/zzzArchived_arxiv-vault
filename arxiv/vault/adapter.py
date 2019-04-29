"""HTTP adapter for use with :class:`hvac.v1.Client`."""

from hvac.adapters import Adapter, Request
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


class HostnameLiberalAdapter(Request):
    """
    Extends :class:`hvac.adapters.Request` to ignore hostnames.

    If we are accessing Vault via one of its nodes' IP addresses, hostname
    verification during the TLS handshake will fail. We still want to verify
    the certificate, we just don't want to have to verify the hostname. For
    background on the painful complexity of TLS with Vault, see
    `https://github.com/hashicorp/vault/issues/764`_.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Mount an :class:`.HostnameLiberalHTTPAdapter` for vault."""
        super(HostnameLiberalAdapter, self).__init__(*args, **kwargs)
        self.session.mount(self.base_uri, HostnameLiberalHTTPAdapter())


class HostnameLiberalHTTPAdapter(HTTPAdapter):
    """Extends :class:`.HTTPAdapter` to ignore hostnames."""

    def init_poolmanager(self, connections, maxsize, block=False):
        """Initialize :class:`.PoolManager` without hostname assertion."""
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize,
                                       block=block, assert_hostname=False)
