"""Overrides HVAC SecretsEngines registry to add :class:`.MySql`."""

from hvac.api.secrets_engines import SecretsEngines as BaseSecretsEngines

from .secrets_engines.mysql import MySql


class SecretsEngines(BaseSecretsEngines):
    """Add support for MySql."""

    implemented_classes = BaseSecretsEngines.implemented_classes + [MySql]
    unimplemented_classes = [
        'Ad',
        'AliCloud',
        'Azure',
        'Consul',
        'Database',
        'Gcp',
        'GcpKms',
        'Nomad',
        'Pki',
        'RabbitMq',
        'Ssh',
        'TOTP',
        'Cassandra',
        'MongoDb',
        'Mssql',
        'PostgreSql',
    ]
