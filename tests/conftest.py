from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.requests import Request

from pybotx_registration.application import HttpsServerHostPolicy, RegistrationService
from pybotx_registration.crypto import InMemoryDeliveryKeyProvider, LocalSecretBoxCipher
from pybotx_registration.presentation import create_registration_router
from pybotx_registration.repository import InMemoryRegistrationRepository


class TestAuthenticator:
    async def authenticate(self, request: Request) -> str:
        return "botx-test-fixture"


@pytest.fixture
def repository() -> InMemoryRegistrationRepository:
    return InMemoryRegistrationRepository()


@pytest.fixture
def delivery_keys() -> InMemoryDeliveryKeyProvider:
    return InMemoryDeliveryKeyProvider.generate()


@pytest.fixture
def storage_cipher() -> LocalSecretBoxCipher:
    return LocalSecretBoxCipher(b"s" * 32, key_id="test-key-v1")


@pytest.fixture
def service(
    repository: InMemoryRegistrationRepository,
    delivery_keys: InMemoryDeliveryKeyProvider,
    storage_cipher: LocalSecretBoxCipher,
) -> RegistrationService:
    return RegistrationService(
        repository=repository,
        delivery_keys=delivery_keys,
        storage_cipher=storage_cipher,
        server_host_policy=HttpsServerHostPolicy(frozenset({"cts.example.internal"})),
    )


@pytest.fixture
def app(service: RegistrationService) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_registration_router(service=service, authenticator=TestAuthenticator())
    )
    return application
