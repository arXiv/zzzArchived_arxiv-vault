"""Provides middleware for getting secrets from Vault."""

from typing import Callable, Dict, Tuple, Iterable, List, Optional, Mapping
from datetime import datetime, timedelta
from pytz import UTC
from functools import partial
import os

import logging

from .core import Vault, Secret
from .manager import SecretsManager

WSGIRequest = Tuple[dict, Callable]

logger = logging.getLogger(__name__)
logger.propagate = False


class VaultMiddleware:
    """
    Middleware for populating Vault secrets on a request.

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

    def __init__(self, wsgi_app: Callable, config: Mapping = {}) -> None:
        """
        Initialize a :class:`.Vault` connection.

        Parameters
        ----------
        app : :class:`.Flask` or callable
            The application wrapped by this middleware. This might be an inner
            middleware, or the original :class:`.Flask` app itself.

        """
        self.app = wsgi_app
        self.config = config
        host = self.config['VAULT_HOST']
        port = self.config['VAULT_PORT']
        scheme = self.config.get('VAULT_SCHEME', 'https')

        self.vault = Vault(host, port, scheme)
        logger.debug('New Vault connection at %s://%s:%s', host, port, scheme)

        self.requests = config.get('VAULT_REQUESTS', [])
        self.secrets = SecretsManager(self.vault, self.requests)
        self.wsgi_app = self

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

    def __call__(self, environ: dict, start_response: Callable) -> Iterable:
        """
        Make sure that all of our secrets are up to date.

        Parameters
        ----------
        environ : dict
            WSGI request environment.
        start_response : function
            Function used to begin the HTTP response. See
            https://www.python.org/dev/peps/pep-0333/#the-start-response-callable

        Returns
        -------
        iterable
            Iterable that generates the HTTP response. See
            https://www.python.org/dev/peps/pep-0333/#the-application-framework-side

        """
        logger.debug('Yield secrets from %s', self.secrets)
        for key, value in self.secrets.yield_secrets(self.token, self.role):
            logger.debug('Got secret %s', key)
            environ[key] = value
        response: Iterable = self.app(environ, start_response)
        return response
