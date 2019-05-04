"""Provides simple Vault API client."""

from typing import Dict, Any, Optional, Union
import os
from pytz import UTC
from datetime import datetime, timedelta
from http import HTTPStatus
import requests
from json.decoder import JSONDecodeError

import hvac
from hvac.adapters import Request as RequestAdapter
from .hvac_extensions import Client
from .adapter import HostnameLiberalAdapter
from .util import getLogger

logger = getLogger(__name__)


class Secret:
    """Represents a secret retrieved from Vault."""

    def __init__(self, value: Any, issued: datetime, lease_id: str,
                 lease_duration: int, renewable: bool) -> None:
        """
        Initialize a new secret.

        Parameters
        ----------
        value : object
            The value of the secret. May be a str value, or a struct of some
            other kind.
        issued : :class:`datetime`
            The time that the secret was issued.
        lease_id : str
            Unique ID for the lease; can be used to renew the lease for the
            secret.
        lease_duration : int
            Duration of the lease in seconds, starting at ``issued``.
        renewable : bool
            Whether or not the lease can be renewed.

        """
        self.value = value
        self.issued = issued
        self.lease_id = lease_id
        self.lease_duration = lease_duration
        self.renewable = renewable

    @property
    def expires(self) -> datetime:
        """Get the datetime that the lease will expire."""
        return self.issued + timedelta(seconds=self.lease_duration)

    def is_expired(self, as_of: Optional[datetime] = None) -> bool:
        """Check whether the token is expired (as of ``as_of``)."""
        if as_of is None:
            as_of = datetime.now(UTC)
        logger.debug('Secret expires at %s; will be expired as of %s?',
                     as_of.isoformat(), self.expires.isoformat())
        return as_of >= self.expires


class Token(Secret):
    """An auth token secret."""


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

    @property
    def authenticated(self) -> bool:
        """Indicate whether or not we are authenticated with Vault."""
        return bool(self._client.is_authenticated())

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

    def renew(self, secret: Secret, increment: int = 3600) -> Secret:
        """Renew a :class:`.Secret`."""
        if not secret.renewable:
            raise RuntimeError('Secret lease is not renewable')
        logger.debug('Renew secret %s for another %i seconds',
                     secret.lease_id, increment)
        data = self._client.sys.renew_lease(lease_id=secret.lease_id,
                                            increment=increment)
        try:    # This may not be everything that we asked for.
            secret.lease_duration = data['data']['lease_duration']
            secret.renewable = data['data']['renewable']
        except KeyError as e:
            raise RuntimeError('Could not use response') from e
        logger.debug('Secret %s renewed for another %i seconds',
                     secret.lease_id, secret.lease_duration)
        return secret

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
                      datetime.now(UTC),
                      data['lease_id'],
                      data['lease_duration'],
                      data['renewable'])

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
                      datetime.now(UTC),
                      data['lease_id'],
                      data['lease_duration'],
                      data['renewable'])

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
                      datetime.now(UTC), lease_id, lease_duration, renewable)
