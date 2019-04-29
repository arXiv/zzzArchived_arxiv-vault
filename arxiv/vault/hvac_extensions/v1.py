"""Extend :class:`hvac.v1.Client` to use extended secrets engines."""

from typing import Any, Optional, Union
import requests
from hvac.v1 import Client as BaseClient
from hvac.adapters import Adapter
from . import api


class Client(BaseClient):
    """Vault client with extended secrets engines."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 cert: Optional[str] = None,
                 verify: Optional[Union[bool, str]] = True,
                 timeout: int = 30, proxies: Optional[dict] = None,
                 allow_redirects: bool = True,
                 session: Optional[requests.Session] = None,
                 adapter: Optional[Union[Adapter, type]] = None,
                 namespace: Optional[str] = None):
        """Initialize with the extended secrets engines."""
        if type(adapter) is type:
            adapter = adapter(
                base_uri=url,
                token=token,
                cert=cert,
                verify=verify,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=allow_redirects,
                session=session,
                namespace=namespace
            )

        super(Client, self).__init__(url, token, cert, verify, timeout,
                                     proxies, allow_redirects, session,
                                     adapter, namespace)
        self._secrets = api.SecretsEngines(adapter=self._adapter)
