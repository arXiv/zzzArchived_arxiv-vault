"""Provides API methods for the :class:`.MySql` secrets engine."""

from typing import Mapping
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT = 'database'


class MySql(VaultApiBase):
    """
    Implements methods for the MySQL/MariaDB secrets engine.

    Reference:
    https://www.vaultproject.io/docs/secrets/databases/mysql-maria.html
    """

    def generate_credentials(self, name: str, endpoint: str = 'creds',
                             mount_point: str = DEFAULT_MOUNT) -> Mapping:
        """Generate new database credentials."""
        resp: Mapping
        resp = self._adapter.get(url=f'/v1/{mount_point}/{endpoint}/{name}')
        return resp

    def read_role(self, name: str, endpoint: str = 'roles',
                  mount_point: str = DEFAULT_MOUNT) -> Mapping:
        """Query the role definition."""
        resp: Mapping
        resp = self._adapter.get(url=f'/v1/{mount_point}/{endpoint}/{name}')
        return resp
