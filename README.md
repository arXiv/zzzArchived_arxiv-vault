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

To use this in WSGI applications, we should also provide a WSGI middleware.

## Installation

Requires Python >= 3.6. To install with pipenv:

```bash
pipenv install arxiv-vault
```

## Usage examples

### In an arXiv Flask application

```python
from flask import Flask
from arxiv.vault.middleware import VaultMiddleware
from arxiv.base.middleware import wrap


def create_app() -> Flask:
    app = Flask(__name__, ...)
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


@celeryd_init.connect   # Runs in the worker right when the daemon starts.
def get_secrets(*args: Any, **kwargs: Any) -> None:
    """Collect any required secrets from Vault."""
    if not app.config['VAULT_ENABLED']:
        print('Vault not enabled; skipping')
        return

    for key, value in get_secrets_manager().yield_secrets():
        app.config[key] = value


@task_prerun.connect    # Runs in the worker before start a task.
def verify_secrets_up_to_date(*args: Any, **kwargs: Any) -> None:
    """Verify that any required secrets from Vault are up to date."""
    if not app.config['VAULT_ENABLED']:
        print('Vault not enabled; skipping')
        return

    for key, value in get_secrets_manager().yield_secrets():
        app.config[key] = value


def get_secrets_manager() -> ConfigManager:
    global __secrets__
    if __secrets__ is None:
        __secrets__ = ConfigManager(app.config)
    return __secrets__

```
