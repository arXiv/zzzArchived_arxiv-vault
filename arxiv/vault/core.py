"""Provides simple Vault API client."""

from typing import Dict, Any, Optional, Union
import os
from http import HTTPStatus
from json.decoder import JSONDecodeError

import requests
from retry import retry
import hvac
from hvac.adapters import Request as RequestAdapter
from .hvac_extensions import Client
from .adapter import HostnameLiberalAdapter
from .util import getLogger
from .domain import Secret, Token, now

logger = getLogger(__name__)


class Vault:
    """A simple Vault API client."""

    kubernetes_mountpoint = 'kubernetes'

    def __init__(self, host: str, port: str, scheme: str = 'https',
                 verify: Union[bool, str] = True) -> None:
        """
        Configure a connection to Vault.

        Parameters
        ----------
        host : str
            Vault host name.
        port : str
            Vault API port number.
        scheme : str
            Default is `https`.
        verify : bool or str
            Passed to client constructor (see :class:`hvac.v1.Client`). If a
            bool, toggles SSL certificate verification. If a str, should be a
            path to a certificate bundle used to verify the server certificate.

        """
        adapter = RequestAdapter
        if scheme == 'https':
            adapter = HostnameLiberalAdapter
        self._client = Client(url=f'{scheme}://{host}:{port}', adapter=adapter,
                              verify=verify)

    @property
    def client(self) -> hvac.v1.Client:
        """Get the current HVAC Vault client."""
        if self._client is None:
            raise RuntimeError('No client; must authenticate')
        return self._client

    # This involves an API call to Vault, so should not be a property.
    def is_authenticated(self) -> bool:
        """Indicate whether or not we are authenticated with Vault."""
        return bool(self._client.is_authenticated())

    @retry(exceptions=ConnectionResetError, tries=30, backoff=2)
    def authenticate(self, kube_token: str, role: str) -> None:
        """
        Authenticate using a Kubernetes token, and obtain a Vault token.

        Parameters
        ----------
        kube_token : str
            Kubernetes service account token. Used to authenticate against the
            Vault cluster using the `Kubernetes Auth Method
            <https://www.vaultproject.io/docs/auth/kubernetes.html>`_.
        role : str
            Name of the Vault role against which to authenticate.

        """
        self._client.auth_kubernetes(role, kube_token,
                                     mount_point=self.kubernetes_mountpoint)

    @retry(exceptions=ConnectionResetError, tries=30, backoff=2)
    def renew(self, secret: Secret, increment: int = 3600) -> Secret:
        """Renew a :class:`.Secret`."""
        if not secret.renewable:
            raise RuntimeError('Secret lease is not renewable')
        logger.debug('Renew secret %s for another %i seconds',
                     secret.lease_id, increment)
        data = self._client.sys.renew_lease(lease_id=secret.lease_id,
                                            increment=increment)
        try:    # This may not be everything that we asked for.
            secret.lease_duration = data['lease_duration']
            secret.issued = now()
            secret.renewable = data['renewable']
        except KeyError as e:
            raise RuntimeError('Could not use response') from e
        logger.debug('Secret %s renewed for another %i seconds',
                     secret.lease_id, secret.lease_duration)
        return secret

    @retry(exceptions=ConnectionResetError, tries=30, backoff=2)
    def generic(self, path: str, key: str,
                mount_point: str = 'secret/') -> Secret:
        """
        Get a generic secret value by key.

        Parameters
        ----------
        path : str
            Path to the secret.
        key : str
            Key within the secret to retrieve.
        mount_point : str
            Path where the KV secrets engine is mounted.

        Returns
        -------
        :class:`.Secret`

        """
        method = self._client.secrets.kv.v2.read_secret_version
        data = method(path=path, mount_point=mount_point)
        return Secret(data['data']['data'][key],
                      now(),
                      data['lease_id'],
                      data['lease_duration'],
                      data['renewable'])

    @retry(exceptions=ConnectionResetError, tries=30, backoff=2)
    def mysql(self, role: str, mount_point: str) -> Secret:
        """
        Get a MySQL secret.

        Parameters
        ----------
        role : str
            Name of the pre-configured database role registered with Vault.
        mount_point : str
            Path where the database secrets engine is mounted.

        Returns
        -------
        :class:`.Secret`

        """
        method = self._client.secrets.mysql
        data = method.generate_credentials(role, mount_point=mount_point)
        secret = (data['data']['username'], data['data']['password'])
        return Secret(secret,
                      now(),
                      data['lease_id'],
                      data['lease_duration'],
                      data['renewable'])

    @retry(exceptions=ConnectionResetError, tries=30, backoff=2)
    def aws(self, role: str, mount_point: str) -> Secret:
        """
        Obtain an AWS credential.

        Parameters
        ----------
        role : str
            Name of the pre-configured AWS policy role registered with Vault.
        mount_point : str
            Path where the AWS secrets engine is mounted.

        Returns
        -------
        :class:`.Secret`

        """
        logger.debug('Obtain an AWS credential for role %s at %s',
                     role, mount_point)
        data = self._client.secrets.aws.generate_credentials(
            name=role,
            mount_point=mount_point
        )
        try:
            aws_access_key_id = data['data']['access_key']
            aws_secret_access_key = data['data']['secret_key']
            lease_id = data['lease_id']
            lease_duration = data['lease_duration']
            renewable = data['renewable']
        except KeyError as e:
            raise RuntimeError('Could not use response') from e
        logger.debug('Obtained credential for role %s with lease %s expiring'
                     ' in %i seconds', role, lease_id, lease_duration)
        return Secret((aws_access_key_id, aws_secret_access_key),
                      now(), lease_id, lease_duration, renewable)
