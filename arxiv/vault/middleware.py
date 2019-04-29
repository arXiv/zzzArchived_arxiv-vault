"""Provides middleware for getting secrets from Vault."""

from typing import Callable, Dict, Tuple, Iterable, List, Optional, Mapping
from datetime import datetime, timedelta
from pytz import UTC
from functools import partial
import os
import warnings

import logging

from .core import Vault, Secret
from .manager import SecretsManager, SecretRequest, ConfigManager


# Monkey-patching `warnings.formatwarning`.
def formatwarning(message, category, filepath, lineno, line=None):
    """Make the warnings a bit prettier."""
    _, filename = os.path.split(filepath)
    return f'arxiv.vault.middleware: {message}\n'


warnings.formatwarning = formatwarning

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
        Initialize a :class:`.Vault` connection using :class:`.ConfigManager`.

        Parameters
        ----------
        app : :class:`.Flask` or callable
            The application wrapped by this middleware. This might be an inner
            middleware, or the original :class:`.Flask` app itself.
        config : mapping
            Configuration from which to obtain Vault parameters and requests.

        """
        self.app = wsgi_app
        self.config = config
        self.secrets = ConfigManager(self.config)
        self.wsgi_app = self

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
        for key, value in self.secrets.yield_secrets():
            logger.debug('Got secret %s', key)
            if environ.get(key) != value:
                warnings.warn(f'Updating {key} with a new value')
            environ[key] = value
            self.config[key] = value
        response: Iterable = self.app(environ, start_response)
        return response
