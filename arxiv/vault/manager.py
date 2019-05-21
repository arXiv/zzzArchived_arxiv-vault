"""Provides :class:`.SecretsManager`."""

from typing import List, Dict, Tuple, Iterable, Optional, Mapping
from dataclasses import dataclass, field
import os
from datetime import datetime, timedelta
import copy
from pytz import UTC

from .util import getLogger
from .core import Vault, Secret
from .domain import SecretRequest, AWSSecretRequest, DatabaseSecretRequest, \
    GenericSecretRequest

logger = getLogger(__name__)

MYSQL = 'mysql'


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
        self._expiry_margin = timedelta(seconds=expiry_margin)
        # Use this flag to limit auth checks.
        self._has_checked_authentication = False

    def _format_database(self, request: DatabaseSecretRequest,
                         secret: Secret) -> str:
        """Format a database secret."""
        username, password = secret.value
        return f'{request.engine}://{username}:{password}@' \
               f'{request.host}:{request.port}/{request.database}?' \
               f'{request.params}'

    def _check_authentication(self, token: str, role: str) -> None:
        """
        Make sure that we are authenticated with vault.

        The flag ``_has_checked_authentication`` is used to avoid making too
        many extraneous auth checks to Vault, e.g. when we are renewing
        multiple secrets in very close succession.
        """
        if self._has_checked_authentication:
            return
        self.vault.authenticate(token, role)
        self._has_checked_authentication = True

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

    def _is_stale(self, request: SecretRequest,
                  secret: Optional[Secret]) -> bool:
        """Determine whether or not a secret requires renewal."""
        return secret is None or \
            (secret.is_expired() and secret.age > (request.minimum_ttl or 0))

    def _get_secret(self, request: SecretRequest, token: str, role: str) \
            -> Secret:
        """Get a secret for a :class:`.SecretRequest`."""
        logger.debug('Get secret for request %s', request.name)
        secret = self.secrets.get(request.name, None)

        # A stale secret is either expired, or has no TTL and the minimum TTL
        # (defined on the secret request) has passed.
        if self._is_stale(request, secret):
            logger.debug('%s is stale; get a fresh one', request)
            # Make sure that we have a current authentication with vault.
            if not self.vault.is_authenticated():
                self._check_authentication(token, role)
            secret = self._fresh_secret(request)

        # We want to anticipate imminent expiration, and either renew or get
        # a new secret before we run into problems.
        elif secret.is_about_to_expire(self._expiry_margin):
            # Make sure that we have a current authentication with vault.
            if not self.vault.is_authenticated():
                self._check_authentication(token, role)

            # If minimum_ttl is set, we want to honor that constraint even
            # if the secret has expired or will expire..
            if secret.age <= (request.minimum_ttl or 0):
                logger.debug('%s about to expire; min TTL not passed', request)
                pass

            elif secret.renewable:
                logger.debug('%s is about to expire; try to renew', request)
                secret = self.vault.renew(secret)
            else:
                logger.debug('%s is about to expire; get a fresh one', request)
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
        # We only want to check our auth status against the Vault API once per
        # call to yield_secrets(); otherwise we end up spamming the API for no
        # good reason. ._check_authentication(...) can use this flag to
        # evaluate whether or not an auth check is warranted.
        self._has_checked_authentication = False
        for request in self.requests:
            secret = self._get_secret(request, tok, role)
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
