"""Tests for :mod:`.domain`."""

from unittest import TestCase
from datetime import datetime, timedelta
from pytz import UTC
from .. import domain


class TestLongLivedSecret(TestCase):
    """We have a non-renewable secret with a very long lease."""

    def setUp(self):
        """Create a new secret."""
        self.value = 'foovalue'
        self.issued = datetime.now(UTC)
        self.duration = 36000
        self.renewable = False
        self.secret = domain.Secret(
            self.value,
            self.issued,
            'foo-lease-id-123',
            self.duration,
            self.renewable
        )

    def test_expires_a_long_time_from_now(self):
        """Test :attr:`Secretion.expires`."""
        self.assertEqual(self.secret.expires,
                         domain.seconds_hence(self.issued, self.duration))

    def test_age(self):
        """Test :attr:`Secretion.age`."""
        self.assertLessEqual(
            self.secret.age - domain.seconds_since(self.issued),
            1e-4
        )

    def test_is_expired(self):
        """Test :func:`.is_expired`."""
        self.assertFalse(self.secret.is_expired())
        self.assertFalse(
            self.secret.is_expired(domain.seconds_hence(self.issued, 30)))
        self.assertFalse(
            self.secret.is_expired(domain.seconds_hence(self.issued, 300)))
        self.assertFalse(
            self.secret.is_expired(domain.seconds_hence(self.issued, 3000)))
        self.assertFalse(
            self.secret.is_expired(domain.seconds_hence(self.issued, 30000)))
        self.assertTrue(
            self.secret.is_expired(domain.seconds_hence(self.issued, 300000)))

    def test_is_about_to_expire(self):
        """Test :func:`.is_about_to_expire`."""
        self.assertFalse(self.secret.is_about_to_expire())
        self.assertFalse(
            self.secret.is_about_to_expire(timedelta(seconds=30)))
        self.assertFalse(
            self.secret.is_about_to_expire(timedelta(seconds=300)))
        self.assertFalse(
            self.secret.is_about_to_expire(timedelta(seconds=3000)))
        self.assertFalse(
            self.secret.is_about_to_expire(timedelta(seconds=30000)))
        self.assertTrue(
            self.secret.is_about_to_expire(timedelta(seconds=300000)))
