"""Tests for :mod:`.manager`."""

from unittest import TestCase, mock
from datetime import datetime
from pytz import UTC

from .. import manager
from ..core import Secret


class TestGetSecretsNotAuthenticated(TestCase):
    """We use a :class:`.SecretsManager` to grab Vault secrets."""

    def setUp(self):
        """We have a :class:`.Vault` connection and are not authenticated."""
        self.vault = mock.MagicMock(authenticated=False)

    def test_generic_request(self):
        """The app requires a generic secret."""
        requests = [{'type': 'generic', 'name': 'GENERIC_FOO', 'path': 'baz',
                     'key': 'foo', 'mount_point': 'foo/'}]
        self.vault.generic.return_value = Secret('foosecret',
                                                 datetime.now(UTC),
                                                 'foolease-1234', 1234, True)
        secrets = manager.SecretsManager(self.vault, requests)

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(yields['GENERIC_FOO'], 'foosecret')
        self.assertEqual(self.vault.generic.call_count, 1)
        self.assertEqual(self.vault.authenticate.call_count, 1)


class TestGetSecrets(TestCase):
    """We use a :class:`.SecretsManager` to grab Vault secrets."""

    def setUp(self):
        """We have a :class:`.Vault` connection and are authenticated."""
        self.vault = mock.MagicMock(authenticated=True)

    def test_generic_request(self):
        """The app requires a generic secret."""
        requests = [{'type': 'generic', 'name': 'GENERIC_FOO', 'path': 'baz',
                     'key': 'foo', 'mount_point': 'foo/'}]
        self.vault.generic.return_value = Secret('foosecret',
                                                 datetime.now(UTC),
                                                 'foolease-1234', 1234, True)
        secrets = manager.SecretsManager(self.vault, requests)

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(yields['GENERIC_FOO'], 'foosecret')
        self.assertEqual(self.vault.generic.call_count, 1)

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.generic.call_count, 1,
                         'Vault is not called a second time, unless...')

        secrets.secrets['GENERIC_FOO'].lease_duration = 0
        self.assertTrue(secrets.secrets['GENERIC_FOO'].is_expired())
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.generic.call_count, 2,
                         '...the lease expires, or...')

        secrets.secrets['GENERIC_FOO'].lease_duration \
            = secrets.expiry_margin.total_seconds() - 5
        self.assertTrue(
            secrets.about_to_expire(secrets.secrets['GENERIC_FOO']),
            '...the secret lease is about to expire...'
        )
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.renew.call_count, 1,
                         'in which case we attempt to renew the lease.')

    def test_aws_request(self):
        """The app requires an AWS credential."""
        requests = [{'type': 'aws', 'name': 'FOO_CREDENTIALS',
                     'role': 'write-foo-s3'}]
        self.vault.aws.return_value = Secret(('fookeyid', 'foosecret'),
                                             datetime.now(UTC),
                                             'foolease-1234', 1234, True)
        secrets = manager.SecretsManager(self.vault, requests)

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(yields['AWS_ACCESS_KEY_ID'], 'fookeyid')
        self.assertEqual(yields['AWS_SECRET_ACCESS_KEY'], 'foosecret')

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.aws.call_count, 1,
                         'Vault is not called a second time, unless...')

        secrets.secrets['FOO_CREDENTIALS'].lease_duration = 0
        self.assertTrue(secrets.secrets['FOO_CREDENTIALS'].is_expired())
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.aws.call_count, 2,
                         '...the lease expires.')

        secrets.secrets['FOO_CREDENTIALS'].lease_duration \
            = secrets.expiry_margin.total_seconds() - 5
        self.assertTrue(
            secrets.about_to_expire(secrets.secrets['FOO_CREDENTIALS']),
            '...the secret lease is about to expire...'
        )
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.renew.call_count, 1,
                         'in which case we attempt to renew the lease.')

    def test_mysql_credentials(self):
        """The app requires a MySQL credential."""
        requests = [{'type': 'database', 'name': 'FOO_DATABASE_URI',
                     'engine': manager.MYSQLDB, 'endpoint': 'foo-database-dev',
                     'role': 'foo-reader', 'host': 'fooserver', 'port': '3306',
                     'database': 'foodb', 'params': 'charset=utf8mb4'}]
        self.vault.mysql.return_value = Secret(('user', 'pass'),
                                               datetime.now(UTC),
                                               'foolease-1234', 1234, True)
        secrets = manager.SecretsManager(self.vault, requests)

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(
            yields['FOO_DATABASE_URI'],
            'mysql+mysqldb://user:pass@fooserver:3306/foodb?charset=utf8mb4'
        )

        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.mysql.call_count, 1,
                         'Vault is not called a second time, unless...')

        secrets.secrets['FOO_DATABASE_URI'].lease_duration = 0
        self.assertTrue(secrets.secrets['FOO_DATABASE_URI'].is_expired())
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.mysql.call_count, 2,
                         '...the lease expires.')

        secrets.secrets['FOO_DATABASE_URI'].lease_duration \
            = secrets.expiry_margin.total_seconds() - 5
        self.vault.renew.return_value = Secret(('user', 'pass'),
                                               datetime.now(UTC),
                                               'foolease-1234', 1234, True)
        self.assertTrue(
            secrets.about_to_expire(secrets.secrets['FOO_DATABASE_URI']),
            '...the secret lease is about to expire...'
        )
        yields = {k: v for k, v in secrets.yield_secrets('tôken', 'röle')}
        self.assertEqual(self.vault.renew.call_count, 1,
                         'in which case we attempt to renew the lease.')
