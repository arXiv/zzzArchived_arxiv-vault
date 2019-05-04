"""Tests for :mod:`.middlware`."""

from unittest import TestCase, mock
import time

from flask import Flask

from arxiv.base.middleware import wrap
from .. import middleware, core


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


class TestWithRealResponse(TestCase):
    def setUp(self):
        """We have a flask app."""
        self.app = Flask(__name__)
        self.app.config['VAULT_HOST'] = 'foohost'
        self.app.config['VAULT_PORT'] = '1234'
        self.app.config['VAULT_CERT'] = '/path/to/cert'
        self.app.config['VAULT_REQUESTS'] = [{
            'type': 'aws',
            'name': 'FOO_CREDENTIALS',
            'role': 'write-foo-s3',
            'mount_point': 'aws-mountpoint'
        }]
        self.app.config['VAULT_ROLE'] = 'foovaultrole'
        self.app.config['KUBE_TOKEN'] = 'fookubetoken1234'

    @mock.patch(f'{core.__name__}.Client')
    def test_request_with_long_tll(self, mClient):
        """Only one request for a secret should be made if not expired."""
        mClient.return_value.secrets.aws.generate_credentials.return_value = {
            "request_id": "a-request-id",
            "lease_id": "aws/creds/role/a-lease-id",
            "renewable": True,
            "lease_duration": 86400,
            "data": {
                "access_key": "ASDF1234",
                "secret_key": "xljadslklk3mlkmlkmxklmx09j3990j",
                "security_token": None
            },
            "wrap_info": None,
            "warnings": None,
            "auth": None
        }

        wrap(self.app, [middleware.VaultMiddleware])
        client = self.app.test_client()

        for _ in range(500):
            with self.app.app_context():
                client.get('/')

        self.assertEqual(
            mClient.return_value.secrets.aws.generate_credentials.call_count,
            1,
            "Only one request should be made, since the TTL has not passed"
        )
        self.assertEqual(mClient.return_value.sys.renew_lease.call_count, 0)

    @mock.patch(f'{core.__name__}.Client')
    def test_request_with_short_tll(self, mClient):
        """A request should be made every time the TTL has passed."""
        mClient.return_value.secrets.aws.generate_credentials.return_value = {
            "request_id": "a-request-id",
            "lease_id": "aws/creds/role/a-lease-id",
            "renewable": True,
            "lease_duration": 0.1,
            "data": {
                "access_key": "ASDF1234",
                "secret_key": "xljadslklk3mlkmlkmxklmx09j3990j",
                "security_token": None
            },
            "wrap_info": None,
            "warnings": None,
            "auth": None
        }

        wrap(self.app, [middleware.VaultMiddleware])
        client = self.app.test_client()

        for _ in range(5):
            time.sleep(0.1)
            with self.app.app_context():
                client.get('/')

        self.assertGreaterEqual(
            mClient.return_value.secrets.aws.generate_credentials.call_count,
            5,
            "At least five requests should be made, since each request came"
            " after about the TTL had passed."
        )
