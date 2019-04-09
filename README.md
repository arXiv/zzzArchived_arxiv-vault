# Vault integration for Python apps

Flask applications need to be able to obtain sensitive information from Vault
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

The integration should run once when the WSGI application is started, and then
monitor the passage of time relative to the lease duration on each secret that
it retrieves (e.g. as a middleware) and automatically refresh the credential(s)
as needed.
