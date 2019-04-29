# Vault integration for Python apps

Applications need to be able to obtain sensitive information from Vault
via its API. Handling this outside of the application is a bit janky; either a
sidecar process is required, or the app must be periodically killed and
restarted with fresh secrets (e.g. database credentials).

The goal of this project is to reduce the complexity of using vault secrets
implementing a lightweight integration. It should accept the following
parameters:

- Auth token (can be passed in as an env var)
- Vault endpoint and port number
- The name of the Vault role that the application requires

It should be configurable to retrieve the followings kinds of secrets:
- AWS credentials bound to a specific policy in Vault
- Database credentials provisioned by Vault
- Generic secrets (key/value)

This package should provide a secrets manager that retrieves secrets, holds on
to them, monitors the passage of time relative to the lease duration on each
secret that it retrieves, and automatically refresh the credential(s) as
needed.

So that we can easily use this package in WSGI applications, it should also
provide a WSGI middleware.

## Installation

Requires Python >= 3.6. To install with pipenv:

```bash
pipenv install arxiv-vault
```

## Notes on terminology

The [Vault documentation](https://www.vaultproject.io/docs/) is remarkably
good. Here are a few notes on terminology that don't jump right off the page
the first time you thread through those docs.

### Mount point vs path vs key

Vault has a whole bunch of pluggable functionality, and it is up to you to
enable the features (e.g. auth methods, secrets engines) that you want. When
you enable a  feature, you assign it to a **mount point**, a path on the Vault
API that will serve as the root path for the API of that feature. For example,
you could enable a [key-value secrets
engine](https://www.vaultproject.io/docs/secrets/kv/kv-v2.html) at the mount
point ``hopes-and-dreams/``; when [reading/writing
data](https://www.vaultproject.io/docs/secrets/kv/kv-v2.html#writing-reading-arbitrary-data),
for example, you would read and write to ``hopes-and-dreams/my-secret-key``.

```bash
vault kv put hopes-and-dreams/my-secret-key my-value=s3cr3t
```

The **path** is the name of the secret relative to that mount point. So,
``my-secret-key`` in the example above is the path. Since kv secrets can
have more than one set of values, **key** refers to the key inside the secret
at path that contains the value of interest.


## Usage examples

### In an arXiv Flask application

```python
from flask import Flask
from arxiv.vault.middleware import VaultMiddleware
from arxiv.base.middleware import wrap


def create_app() -> Flask:
    app = Flask(__name__, ...)
    # Normally this would be in config.py, but for the sake of brevity...
    app.config.update({
        'KUBE_TOKEN': '/path/to/ServiceAccount/token',
        'VAULT_HOST': 'foohost',
        'VAULT_PORT': '8200',
        'VAULT_ROLE': 'my-app-role',
        'VAULT_CERT': '/path/to/cert',
        'VAULT_REQUESTS': [
            {
                'type': 'generic',
                'name': 'JWT_SECRET',
                'mount_point': 'wherethesecretslive/',
                'path': 'jwt',
                'key': 'secret'
            },
            {
                'type': 'database',
                'name': 'FOO_DATABASE_URI',
                'engine': 'mysql+mysqldb',
                'mount_point': 'foo-database-dev/',
                'role': 'foo-db-role',
                'host': 'fooserver',
                'port': '3306',
                'database': 'foodb',
                'params': 'charset=utf8mb4'
            }
        ]
    })
    ...

    wrap(app, [VaultMiddleware])
    ...
    return app


```

### In a Celery worker

```python
from celery.signals import task_prerun, celeryd_init, worker_init

from arxiv.vault.manager import ConfigManager
from .factory import create_app
from .celery import celery_app

__secrets__ = None
__app__ = create_app()

# Normally this would be in config.py, but for the sake of brevity...
__app__.config.update({
    'KUBE_TOKEN': '/path/to/ServiceAccount/token',
    'VAULT_HOST': 'foohost',
    'VAULT_PORT': '8200',
    'VAULT_ROLE': 'my-app-role',
    'VAULT_CERT': '/path/to/cert',
    'VAULT_REQUESTS': [
        {
            'type': 'generic',
            'name': 'JWT_SECRET',
            'mount_point': 'wherethesecretslive/',
            'path': 'jwt',
            'key': 'secret'
        },
        ...
    ]
})


@celeryd_init.connect   # Runs in the worker right when the daemon starts.
def get_secrets(*args: Any, **kwargs: Any) -> None:
    """Collect any required secrets from Vault."""
    if not __app__.config['VAULT_ENABLED']:
        print('Vault not enabled; skipping')
        return

    for key, value in get_secrets_manager().yield_secrets():
        __app__.config[key] = value


@task_prerun.connect    # Runs in the worker before start a task.
def verify_secrets_up_to_date(*args: Any, **kwargs: Any) -> None:
    """Verify that any required secrets from Vault are up to date."""
    if not __app__.config['VAULT_ENABLED']:
        print('Vault not enabled; skipping')
        return

    for key, value in get_secrets_manager().yield_secrets():
        __app__.config[key] = value


def get_secrets_manager() -> ConfigManager:
    global __secrets__
    if __secrets__ is None:
        __secrets__ = ConfigManager(__app__.config)
    return __secrets__

```

## Documentation

### Building

```bash
sphinx-apidoc -o docs/source/api/arxiv.vault -e -f -M --implicit-namespaces arxiv *test*/*
cd docs/
make html SPHINXBUILD=$(pipenv --venv)/bin/sphinx-build
```
