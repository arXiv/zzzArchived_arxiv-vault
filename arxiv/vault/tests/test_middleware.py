"""Tests for :mod:`.middlware`."""

from unittest import TestCase, mock

from flask import Flask

from arxiv.base.middleware import wrap
from .. import middleware


class TestMiddlewareMisconfigured(TestCase):
    """Test the case that the app is not configured to use Vault."""

    def test_init(self):
        """The middlware is instantiated."""
        self.app = Flask(__name__)
        with self.assertRaises(KeyError):
            wrap(self.app, [middleware.VaultMiddleware])


class TestMiddleware(TestCase):
    """Test middleware with an app that is configured to use Vault."""

    @mock.patch(f'{middleware.__name__}.ConfigManager')
    def setUp(self, mock_SecretsManager):
        """We have a flask app."""
        self.manager = mock.MagicMock()
        mock_SecretsManager.return_value = self.manager

        self.app = Flask(__name__)
        self.app.config['VAULT_HOST'] = 'foohost'
        self.app.config['VAULT_PORT'] = '1234'
        self.app.config['VAULT_CERT'] = '/path/to/cert'
        self.app.config['VAULT_REQUESTS'] = [{
            'type': 'generic',
            'name': 'JWT_SECRET',
            'mount_point': 'wherethesecretslive',
            'path': 'jwt',
            'key': 'secret'
        }]
        self.app.config['VAULT_ROLE'] = 'foovaultrole'
        self.app.config['KUBE_TOKEN'] = 'fookubetoken1234'
        wrap(self.app, [middleware.VaultMiddleware])
        self.client = self.app.test_client()

    def test_request(self):
        """An HTTP request is received by the app."""
        self.manager.yield_secrets.return_value = [('JWT_SECRET', 'secret')]
        with self.app.app_context():
            self.client.get('/')

        self.assertEqual(self.manager.yield_secrets.call_count, 1,
                         'The SecretsManager is consulted on each request.')

        with self.app.app_context():
            self.client.get('/something/else')

        self.assertEqual(self.manager.yield_secrets.call_count, 2,
                         'The SecretsManager is consulted on each request.')
