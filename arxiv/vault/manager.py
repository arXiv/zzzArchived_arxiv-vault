"""Provides :class:`.SecretsManager`."""

from typing import List, Dict, Tuple, Iterable

from datetime import datetime, timedelta
from pytz import UTC

import logging

from .core import Vault, Secret

logger = logging.getLogger(__name__)
logger.propagate = False

MYSQLDB = 'mysql+mysqldb'


class SecretsManager:
    """
    Fulfills requests for Vault secrets, and manages renewal transparently.

    A typical use case for working with Vault secrets is that we want to
    generate some configuration variables for use at run-time. For example,
    in a Flask application we want things like secret keys and sensitive
    database URIs to be available in the application config when handling a
    request. The goal of the secrets manager is to fulfill requests for
    secrets that will be used in that kind of key-value paradigm.

    The manager should only call Vault if the secret has not been retrieved
    yet, or if the secret is expired or about to expire.

    A request is a description of the secret that is desired and (depending on
    its type) the form in which it should be returned.

    AWS
    ===
    - ``'type': 'aws'``
    - ``'role': 'name-of-preconfigured-aws-policy-role'``

    Example:

    ```python
    manager.requests.append({
        'type': 'aws',
        'role': 'coolapp-write-s3-cooldata'
    })

    for key, value in manager.yield_secrets('sometoken'):
        print(key, value)
    # AWS_ACCESS_KEY_ID asdf12345
    # AWS_SECRET_ACCESS_KEY qwertyuiiop!@#6789
    ```

    Database
    ========
    Returns a full database URI with auth info.

    - ``'type': 'database'``
    - ``'name': 'DATABASE_URI'``
    - ``'endpoint': 'vault-database-endpoint-name'``
    - ``'role': 'read-data-role'``
    - ``'engine': 'engine-name'`` (e.g. ``mysql+mysqldb``)
    - ``'host': 'some-database-server'``
    - ``'port': '3306'``
    - ``'database': 'some-database'``
    - ``'params': 'charset=utf8mb4'``

    Generic
    =======
    - ``'type': 'generic'``
    - ``'name': 'SOME_SECRET'``
    - ``'path': 'some-path-to-a-secret'``
    - ``'key': 'key-for-the-secret'``

    """

    def __init__(self, vault: Vault, requests: List[Dict[str, str]],
                 expiry_margin: int = 300) -> None:
        """Initialize a new manager with :class:`.Vault` connection."""
        self.vault = vault
        self.requests = requests
        self.secrets: Dict[str, Secret] = {}
        self.expiry_margin = timedelta(seconds=expiry_margin)

    def about_to_expire(self, secret: Secret) -> bool:
        """Check if a secret is about to expire within `margin` seconds."""
        return secret.is_expired(datetime.now(UTC) + self.expiry_margin)

    def format_database(self, request: Dict[str, str], secret: Secret) -> str:
        """Format a database secret."""
        username, password = secret.value
        return f'{request["engine"]}://{username}:{password}@' \
               f'{request["host"]}:{request["port"]}/{request["database"]}?' \
               f'{request["params"]}'

    def fresh_secret(self, request: Dict[str, str]) -> Secret:
        """Get a brand new secret."""
        if request['type'] == 'aws':
            secret = self.vault.aws(request['role'])
        elif request['type'] == 'database':
            if request['engine'] == MYSQLDB:
                secret = self.vault.mysql(request['role'], request['endpoint'])
            else:
                raise NotImplementedError('No other database engine available')
        elif request['type'] == 'generic':
            secret = self.vault.generic(request['path'], request['key'])
        return secret

    def yield_secrets(self, tok: str, role: str) -> Iterable[Tuple[str, str]]:
        """Generate config var + secret tuples."""
        # Make sure that we have a current authentication with vault.
        if not self.vault.authenticated:
            self.vault.authenticate(tok, role)

        for request in self.requests:
            name = request['name']
            secret = self.secrets.get(name, None)
            if secret is None or secret.is_expired():
                logger.debug('Secret %s is expired', name)
                secret = self.fresh_secret(request)
            elif self.about_to_expire(secret):
                secret = self.vault.renew(secret)
            self.secrets[name] = secret
            if request['type'] == 'aws':
                yield 'AWS_ACCESS_KEY_ID', secret.value[0]
                yield 'AWS_SECRET_ACCESS_KEY', secret.value[1]
            elif request['type'] == 'database':
                yield name, self.format_database(request, secret)
            elif request['type'] == 'generic':
                yield name, secret.value
