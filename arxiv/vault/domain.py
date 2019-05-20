"""Core concepts of the arXiv Vault integration."""

from typing import Any, Optional
from datetime import datetime, timedelta
from pytz import UTC

from dataclasses import dataclass, field


def now() -> datetime:
    """Get the current datetime."""
    return datetime.now(UTC)


def seconds(from_: datetime, to_: datetime) -> int:
    """Get the number of seconds between two datetimes."""
    return (to_ - from_).total_seconds()


def seconds_since(from_: datetime) -> int:
    """Get the number of seconds that has elapsed since a datetime."""
    return seconds(from_, now())


def seconds_hence(from_: datetime, N_seconds: int) -> datetime:
    """Get a datetime ``N_seconds`` seconds from now."""
    return from_ + timedelta(seconds=N_seconds)


class Secret:
    """Represents a secret retrieved from Vault."""

    default_margin = timedelta(seconds=30)
    """
    This is the default expiry margin for secrets.

    This is the mimimum age that a secret must reach before it can be renewed.
    This allows us to prevent extraneous renewals for secrets with no explicit
    TTL.
    """

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

    @property
    def age(self) -> int:
        """Get the amount of time in seconds since the secret was issued."""
        return (now() - self.issued).total_seconds()

    def is_expired(self, as_of: Optional[datetime] = None) -> bool:
        """Check whether the token is expired (as of ``as_of``)."""
        if as_of is None:
            as_of = now()
        return as_of >= self.expires

    def is_about_to_expire(self,  margin: timedelta = default_margin) -> bool:
        """Check if a secret is about to expire within `margin`."""
        return self.is_expired(now() + margin)


class Token(Secret):
    """An auth token secret."""


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

    minimum_ttl: int = field(default=0)
    """Renewal will be attempted no more frequently than ``minimum_ttl``."""

    def __repr__(self) -> str:
        """Get the string representation of this secret request."""
        return f'{self.slug}:{self.mount_point}:{self.role}'


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

    minimum_ttl: int = field(default=0)
    """Renewal will be attempted no more frequently than ``minimum_ttl``."""

    def __repr__(self) -> str:
        """Get the string representation of this secret request."""
        return f'{self.slug}:{self.mount_point}:{self.engine}:{self.role}'


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

    def __repr__(self) -> str:
        """Get the string representation of this secret request."""
        return f'{self.slug}:{self.mount_point}:{self.path}:{self.key}'
