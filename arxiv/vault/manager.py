"""Provides :class:`.SecretsManager`."""

from typing import List, Dict, Tuple, Iterable, Optional, Mapping
from dataclasses import dataclass, field
import os
from datetime import datetime, timedelta
import copy
from pytz import UTC

from .util import getLogger
from .core import Vault, Secret

logger = getLogger(__name__)

MYSQL = 'mysql'


@dataclass
class SecretRequest:
    """Represents a request for a secret from Vault."""

    name: str

    @classmethod
    def factory(cls, request_type: str, **data: str) -> 'SecretRequest':
        """Genereate a request of the appropriate type."""
        for klass in cls.__subclasses__():
            if klass.slug == request_type:
                return klass(**data)
        raise ValueError('No such request type')


@dataclass
class AWSSecretRequest(SecretRequest):
    """Represents a request for AWS credentials."""

    slug = "aws"

    role: str
    """An AWS role that has been pre-configured with IAM policies in Vault."""

    mount_point: str = field(default='aws/')
    """Path where the AWS secrets engine is mounted."""


@dataclass
class DatabaseSecretRequest(SecretRequest):
    """Represents a request for database credentials."""

    slug = "database"

    role: str
    """Name of the database role for which to obtain credentials."""

    engine: str
    """
    Database dialect for which secret is required, e.g. ``mysql+mysqldb``.

    See https://docs.sqlalchemy.org/en/13/core/engines.html#database-urls
    """

    host: str
    """Hostname of the database server."""

    port: str
    """Port number of the database server."""

    database: str
    """Name of the database."""

    params: str
    """Param-part of the database URI connection string."""

    mount_point: str = field(default='database/')
    """Path where the database secrets engine is mounted."""


@dataclass
class GenericSecretRequest(SecretRequest):
    """Represents a request for a generic (kv) secret."""

    slug = "generic"

    path: str
    """Path to the secret."""

    key: str
    """Key within the secret."""

    mount_point: str = field(default='secret/')
    """Mount point of the KV engine."""

    minimum_ttl: int = field(default=0)
    """Renewal will be attempted no more frequently than ``minimum_ttl``."""


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

    Should be one of:

    - :class:`.AWSSecretRequest`
    - :class:`.DatabaseSecretRequest`
    - :class:`.GenericSecretRequest`

    """

    def __init__(self, vault: Vault, requests: List[SecretRequest],
                 expiry_margin: int = 30) -> None:
        """Initialize a new manager with :class:`.Vault` connection."""
        self.vault = vault
        self.requests = requests
        self.secrets: Dict[str, Secret] = {}
        self.expiry_margin = timedelta(seconds=expiry_margin)

    def _about_to_expire(self, secret: Secret) -> bool:
        """Check if a secret is about to expire within `margin` seconds."""
        as_of = datetime.now(UTC) + self.expiry_margin
        logger.debug('Check lease %s expiry as of %s (%s seconds from now)',
                     secret.lease_id, as_of, self.expiry_margin)
        return secret.is_expired(as_of)

    def _format_database(self, request: DatabaseSecretRequest,
                         secret: Secret) -> str:
        """Format a database secret."""
        username, password = secret.value
        return f'{request.engine}://{username}:{password}@' \
               f'{request.host}:{request.port}/{request.database}?' \
               f'{request.params}'

    def _fresh_secret(self, request: SecretRequest) -> Secret:
        """Get a brand new secret."""
        if type(request) is AWSSecretRequest:
            secret = self.vault.aws(request.role, request.mount_point)
        elif type(request) is DatabaseSecretRequest:
            if request.engine.split('+', 1)[0] == MYSQL:
                secret = self.vault.mysql(request.role, request.mount_point)
            else:
                raise NotImplementedError('No other database engine available')
        elif type(request) is GenericSecretRequest:
            secret = self.vault.generic(request.path, request.key,
                                        request.mount_point)
        return secret

    def _can_freshen(self, request: SecretRequest, secret: Secret) -> bool:
        """Enforce minimum TTL."""
        if not hasattr(request, 'minimum_ttl'):
            return True
        age = (datetime.now(UTC) - secret.issued).total_seconds()
        return age >= request.minimum_ttl

    def _is_stale(self, request: SecretRequest,
                  secret: Optional[Secret]) -> bool:
        """Determine whether or not a secret requires renewal."""
        return secret is None or \
            (secret.is_expired() and self._can_freshen(request, secret))

    def _get_secret(self, request: SecretRequest) -> Secret:
        """Get a secret for a :class:`.SecretRequest`."""
        logger.debug('Get secret for request %s', request.name)
        secret = self.secrets.get(request.name, None)
        if self._is_stale(request, secret):
            logger.debug('Secret is stale; get a fresh one')
            secret = self._fresh_secret(request)
        elif self._about_to_expire(secret):
            if secret.renewable:
                logger.debug('Secret is about to expire; try to renew')
                secret = self.vault.renew(secret)
            else:
                logger.debug('Secret is about to expire; get a fresh one')
                secret = self._fresh_secret(request)
        self.secrets[request.name] = secret
        return secret

    def yield_secrets(self, tok: str, role: str) -> Iterable[Tuple[str, str]]:
        """
        Generate config var + secret tuples.

        Parameters
        ----------
        token : str
            Token for authenticating with Vault. For example, the Kubernetes
            ServiceAccount token used to authenticate with the Kubernetes
            auth method.
        role : str
            The name of the Vault role associated with the token.

        """
        # Make sure that we have a current authentication with vault.
        if not self.vault.authenticated:
            self.vault.authenticate(tok, role)

        for request in self.requests:
            secret = self._get_secret(request)
            if type(request) is AWSSecretRequest:
                yield 'AWS_ACCESS_KEY_ID', secret.value[0]
                yield 'AWS_SECRET_ACCESS_KEY', secret.value[1]
            elif type(request) is DatabaseSecretRequest:
                yield request.name, self._format_database(request, secret)
            elif type(request) is GenericSecretRequest:
                yield request.name, secret.value


class ConfigManager:
    """
    Manages access to secrets in Vault based on env-style configuration.

    Config parameters:

    - ``KUBE_TOKEN``, used to authenticate against the Kubernetes Auth
      endpoint.
    - ``VAULT_HOST``
    - ``VAULT_PORT``
    - ``VAULT_REQUESTS``; see :class:`.SecretsManager` for how these should be
      expressed.
    - ``VAULT_SCHEME`` (optional; defaults to 'https')

    TODO: expand support for additional auth methods.
    """

    def __init__(self, config: Mapping) -> None:
        """
        Initialize a :class:`.Vault` connection.

        Parameters
        ----------
        config : mapping
            Configuration from which to obtain Vault parameters and requests.

        """
        self.config = config
        host = self.config['VAULT_HOST']
        port = self.config['VAULT_PORT']
        cert = self.config['VAULT_CERT']

        scheme = self.config.get('VAULT_SCHEME', 'https')
        self.vault = Vault(host, port, scheme, verify=cert)
        logger.debug('New Vault connection at %s://%s:%s', host, port, scheme)
        self.requests = self._get_requests(config)
        self.secrets = SecretsManager(self.vault, self.requests)

    @property
    def token(self) -> str:
        """Kubernetes token."""
        tok = str(self.config['KUBE_TOKEN'])
        if os.path.exists(tok):     # May be a path to the token on disk.
            with open(tok) as f:
                return f.read()
        return tok

    @property
    def role(self) -> str:
        """Vault role."""
        return str(self.config['VAULT_ROLE'])

    def _get_requests(self, config: Mapping) -> List[SecretRequest]:
        requests: List[SecretRequest] = []
        for req_data in config.get('VAULT_REQUESTS', []):
            req_data = copy.deepcopy(req_data)
            req_type = req_data.pop('type')
            requests.append(SecretRequest.factory(req_type, **req_data))
        return requests

    def yield_secrets(self) -> Iterable[Tuple[str, str]]:
        """Yield secrets from the :class:`.SecretsManager`."""
        return self.secrets.yield_secrets(self.token, self.role)
