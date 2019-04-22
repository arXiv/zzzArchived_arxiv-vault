# Decision log for arXiv Vault

- 2019-04-02. **No arXiv/Flask dependencies.** This package should be as nimble
  as possible. Since its core features/requirements are generic, and there is
  no arXiv- or Flask-specific domain logic that needs to be leveraged here,
  we will not include standard arXiv-NG dependencies like Flask or arXiv Base as part of the production packages. They may be included for development and testing purposes (`dev-packages`).
