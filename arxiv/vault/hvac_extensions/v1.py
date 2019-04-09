"""Extend :class:`hvac.v1.Client` to use extended secrets engines."""

from typing import Any
from hvac.v1 import Client as BaseClient
from . import api


class Client(BaseClient):
    """Vault client with extended secrets engines."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize with the extended secrets engines."""
        super(Client, self).__init__(*args, **kwargs)
        self._secrets = api.SecretsEngines(adapter=self._adapter)
