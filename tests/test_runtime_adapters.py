from __future__ import annotations

import pytest
from nacl.public import PrivateKey, SealedBox
from starlette.requests import Request

from pybotx_registration.application import HttpsServerHostPolicy
from pybotx_registration.auth import AllowlistedPeerAuthenticator
from pybotx_registration.container import RegistrationContainer
from pybotx_registration.crypto import InMemoryDeliveryKeyProvider, LocalSecretBoxCipher
from pybotx_registration.domain import (
    EncryptedSecret,
    InvalidRegistrationRequestError,
    RegistrationAuthenticationError,
    SecretDecryptionError,
)


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


def test__registration_container__builds_the_service_from_configuration() -> None:
    container = RegistrationContainer()
    container.config.storage_key.from_value(b"s" * 32)
    container.config.allowed_cts_hosts.from_value(frozenset({"cts.example.internal"}))

    service = container.service()

    assert service is container.service()
