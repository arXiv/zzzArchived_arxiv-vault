"""Tests for :mod:`.core`."""

from unittest import TestCase, mock
from .. import domain, core, adapter
import requests
import hvac


class TestAuthenticate(TestCase):
    """The :class:`.core.Vault` client authenticates with vault."""

    def setUp(self):
        """We have a :class:`.core.Vault` client for a specific Vault host."""
        self.client = core.Vault('foohost', '8200', 'https', verify=True)

    def test_is_not_authenticated(self):
        """The client is not authenticated at first."""
        self.assertFalse(self.client.is_authenticated())

    @mock.patch('requests.Session.send')
    def test_authenticate(self, mock_send):
        """We can authenticate with a Kubernetes auth token."""
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(
                return_value={'auth': {'client_token': 'footoken'}}
            )
        )
        self.client.authenticate('footoken', 'foo-service-role')
        self.assertTrue(self.client.is_authenticated())

    @mock.patch('requests.Session.send')
    def test_cannot_authenticate(self, mock_send):
        """An :class:`hvac.exceptions.Forbidden` exception is raised."""
        mock_send.return_value = mock.MagicMock(
            status_code=403,
            json=mock.MagicMock(return_value={})
        )
        with self.assertRaises(hvac.exceptions.Forbidden):
            self.client.authenticate('footoken', 'foo-service-role')
        self.assertFalse(self.client.is_authenticated())


class TestRenew(TestCase):
    """The :class:`.core.Vault` client supports renewing secrets."""

    @mock.patch('requests.Session.send')
    def setUp(self, mock_send):
        """We have a :class:`.core.Vault` client for a specific Vault host."""
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(
                return_value={'auth': {'client_token': 'footoken'}}
            )
        )
        self.client = core.Vault('foohost', '8200', 'https', verify=True)
        self.client.authenticate('footoken', 'foo-service-role')

    def test_renew_an_unrenewable_secret(self):
        """No attempt is made to renew an unrenewable secret."""
        unrenewable = domain.Secret('foo', domain.now(), 'foo', 3600, False)
        with self.assertRaises(RuntimeError):
            self.client.renew(unrenewable)

    @mock.patch('requests.Session.send')
    def test_renew_renable_secret(self, mock_send):
        """Renewable secrets may be renewed."""
        renewable = domain.Secret('foo', domain.now(), 'foo', 3600, True)
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(return_value={
              "lease_id": "aws/creds/deploy/abcd-1234...",
              "renewable": True,
              "lease_duration": 2764790
            })
        )
        secret = self.client.renew(renewable)
        self.assertFalse(secret.is_expired())
        self.assertEqual(secret.expires,
                         domain.seconds_hence(secret.issued, 2764790))

    @mock.patch('requests.Session.send')
    def test_malformed_response(self, mock_send):
        """Vault craps out and returns some odd data."""
        renewable = domain.Secret('foo', domain.now(), 'foo', 3600, True)
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(return_value={})
        )
        with self.assertRaises(RuntimeError):
            secret = self.client.renew(renewable)


class TestMySQL(TestCase):
    """The :class:`.core.Vault` client supports MySQL credentials."""

    @mock.patch('requests.Session.send')
    def setUp(self, mock_send):
        """We have a :class:`.core.Vault` client for a specific Vault host."""
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(
                return_value={'auth': {'client_token': 'footoken'}}
            )
        )
        self.client = core.Vault('foohost', '8200', 'https', verify=True)
        self.client.authenticate('footoken', 'foo-service-role')

    @mock.patch('requests.Session.send')
    def test_get_mysql_secret(self, mock_send):
        """Get a MySQL secret."""
        mock_send.return_value = mock.MagicMock(
            status_code=200,
            json=mock.MagicMock(
                return_value={
                    'data': {'username': 'foouser', 'password': 'foopassword'},
                    'lease_id': 'foo-lease-123',
                    'lease_duration': 5000,
                    'renewable': True
                }
            )
        )
        secret = self.client.mysql('foo-db-role', 'foopoint/')
        self.assertFalse(secret.is_expired())
