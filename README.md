# pybotx-registration

Implementation foundation for the BotX automatic secret-delivery protocol:

- `GET /public_key` returns a Base64-encoded Libsodium public key;
- `POST /register` accepts a sealed `secret_key` and persists it only after
  re-encrypting it for storage;
- duplicate registration never changes an existing credential;
- the request path is authenticated, bounded and validates `server_host` before
  it becomes an outbound endpoint.

The package deliberately has no business handlers and no access to a plaintext
secret outside its account-provider boundary.


## Local verification

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

The tests exercise real Libsodium sealed-box encryption/decryption, HTTP
contract responses, durable-at-service-boundary storage semantics, duplicate
and concurrent delivery, lifecycle transitions, and the pybotx API gate.

## Production adapters

`InMemoryRegistrationRepository` and `LocalSecretBoxCipher` are test/dev
adapters only. Before deployment replace them with a PostgreSQL repository
with `UNIQUE(server_id, bot_id)` and a KMS/Vault envelope-encryption adapter.
Use mTLS or `AllowlistedPeerAuthenticator` on a directly connected,
correctly terminated private-network ingress for the router.
