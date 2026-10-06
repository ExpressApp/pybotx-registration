from __future__ import annotations

import base64
from pathlib import Path

import pytest
from dependency_injector import providers
from nacl.public import PrivateKey, SealedBox
from starlette.requests import Request

from pybotx_registration.application import HttpsServerHostPolicy, RegisterBotCommand
from pybotx_registration.auth import AllowlistedPeerAuthenticator
from pybotx_registration.container import (
    RegistrationContainer,
    build_registration_service,
    initialize_registration_runtime,
)
from pybotx_registration.crypto import (
    InMemoryDeliveryKeyProvider,
    LocalKeyStore,
    LocalSecretBoxCipher,
)
from pybotx_registration.domain import (
    AccountKey,
    EncryptedSecret,
    InvalidRegistrationRequestError,
    RegistrationAuthenticationError,
    SecretDecryptionError,
)
from pybotx_registration.repository import InMemoryRegistrationRepository


class _KeyMaterial:
    def __init__(self) -> None:
        self._values = {
            "delivery_private_key_v1": bytes(PrivateKey.generate()),
            "storage_secretbox_key_v1": b"s" * 32,
        }

    async def get_or_create(self, name: str, *, size: int) -> bytes:
        value = self._values[name]
        assert len(value) == size
        return value


class _DisposableEngine:
    def __init__(self) -> None:
        self.disposed = False

    async def dispose(self) -> None:
        self.disposed = True


def _request(client: tuple[str, int] | None) -> Request:
    scope: dict[str, object] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
    }
    if client is not None:
        scope["client"] = client
    return Request(scope)


def test__https_server_host_policy__rejects_invalid_hosts_and_normalizes_valid_one(
) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        HttpsServerHostPolicy(frozenset())

    policy = HttpsServerHostPolicy(frozenset({"cts.example.internal"}))
    assert policy.validate("https://CTS.EXAMPLE.INTERNAL:443/") == (
        "https://cts.example.internal"
    )

    for endpoint in (
        "http://cts.example.internal",
        "https://user@cts.example.internal",
        "https://cts.example.internal/path",
        "https://cts.example.internal:8443",
        "https://cts.example.internal:invalid",
    ):
        with pytest.raises(InvalidRegistrationRequestError):
            policy.validate(endpoint)


@pytest.mark.asyncio
async def test__allowlisted_peer_authenticator__handles_trusted_and_invalid_clients(
) -> None:
    with pytest.raises(ValueError, match="source network"):
        AllowlistedPeerAuthenticator(frozenset())

    authenticator = AllowlistedPeerAuthenticator(frozenset({"10.0.0.0/8"}))
    assert await authenticator.authenticate(_request(("10.1.2.3", 443))) == (
        "network:10.1.2.3"
    )

    for client in (None, ("invalid-ip", 443), ("192.168.1.2", 443)):
        with pytest.raises(RegistrationAuthenticationError):
            await authenticator.authenticate(_request(client))


@pytest.mark.asyncio
async def test__secret_adapters__reject_invalid_ciphertexts_and_storage_keys() -> None:
    delivery_keys = InMemoryDeliveryKeyProvider.generate()
    with pytest.raises(SecretDecryptionError, match="sealed secret"):
        await delivery_keys.decrypt_sealed(b"not-a-sealed-box")

    with pytest.raises(ValueError, match="storage key"):
        LocalSecretBoxCipher(b"too-short")

    cipher = LocalSecretBoxCipher(b"k" * 32, key_id="key-a")
    with pytest.raises(SecretDecryptionError, match="unknown storage key"):
        await cipher.decrypt(EncryptedSecret(ciphertext=b"irrelevant", key_id="key-b"))
    with pytest.raises(SecretDecryptionError, match="stored secret"):
        await cipher.decrypt(
            EncryptedSecret(ciphertext=b"not-a-secret-box", key_id="key-a")
        )

    private_key = PrivateKey.generate()
    ciphertext = SealedBox(private_key.public_key).encrypt(b"secret")
    provider = InMemoryDeliveryKeyProvider(private_key)
    assert await provider.decrypt_sealed(ciphertext) == b"secret"


def test__registration_container__builds_durable_components_from_configuration(
    tmp_path: Path,
) -> None:
    container = RegistrationContainer()
    container.config.from_dict(
        {
            "postgres_dsn": "postgresql+asyncpg://registration:password@db/registration",
            "key_directory": str(tmp_path / "keys"),
            "allowed_cts_hosts": frozenset({"cts.example.internal"}),
        }
    )

    repository = container.repository()
    root_key = container.root_key()
    policy = container.server_host_policy()

    assert repository is container.repository()
    assert root_key == container.root_key()
    assert len(root_key) == 32
    assert policy.validate("https://cts.example.internal") == "https://cts.example.internal"


def test__local_root_key__survives_store_recreation(tmp_path: Path) -> None:
    key_directory = tmp_path / "keys"
    first_store = LocalKeyStore(key_directory)
    root_key = first_store.get_or_create("root_key", size=32)

    second_store = LocalKeyStore(key_directory)
    restored_root_key = second_store.get_or_create("root_key", size=32)

    assert root_key == restored_root_key
    assert (key_directory / "root_key").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test__container__restores_keys_and_verifies_credentials_before_ready(
    tmp_path: Path,
) -> None:
    repository = InMemoryRegistrationRepository()
    key_material = _KeyMaterial()
    engine = _DisposableEngine()
    container = RegistrationContainer()
    container.config.from_dict(
        {
            "postgres_dsn": "postgresql+asyncpg://registration:password@db/registration",
            "key_directory": str(tmp_path / "keys"),
            "allowed_cts_hosts": frozenset({"cts.example.internal"}),
        }
    )
    container.repository.override(providers.Object(repository))
    container.key_material.override(providers.Object(key_material))
    container.engine.override(providers.Object(engine))

    first_service = await build_registration_service(container)
    public_key = PrivateKey(key_material._values["delivery_private_key_v1"]).public_key
    ciphertext = SealedBox(public_key).encrypt(b"durable-secret")
    await first_service.register(
        RegisterBotCommand(
            bot_id="bot-a",
            server_id="cts-a",
            server_host="https://cts.example.internal",
            encrypted_secret_key=base64.b64encode(ciphertext).decode(),
        )
    )

    runtime = await initialize_registration_runtime(container)
    await runtime.shutdown()

    reset = await runtime.service.reset(AccountKey("cts-a", "bot-a"))

    assert reset.account_key == AccountKey("cts-a", "bot-a")
    assert engine.disposed
