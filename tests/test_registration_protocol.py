from __future__ import annotations

import asyncio
import base64

import httpx
import pytest
from fastapi import FastAPI
from nacl.public import PublicKey, SealedBox
from starlette.requests import Request

from pybotx_registration.application import RegisterBotCommand, RegistrationService
from pybotx_registration.crypto import InMemoryDeliveryKeyProvider, LocalSecretBoxCipher
from pybotx_registration.domain import (
    AccountKey,
    RegistrationAuthenticationError,
    RegistrationStatus,
)
from pybotx_registration.presentation import create_registration_router
from pybotx_registration.repository import InMemoryRegistrationRepository


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://bot.example.internal"
    )


async def _sealed_payload(
    client: httpx.AsyncClient, secret: bytes = b"very-secret"
) -> str:
    response = await client.get("/public_key")
    assert response.status_code == 200
    public_key = PublicKey(base64.b64decode(response.json()["result"], validate=True))
    return base64.b64encode(SealedBox(public_key).encrypt(secret)).decode("ascii")


@pytest.mark.asyncio
async def test_register_uses_real_sealed_box_and_persists_only_storage_ciphertext(
    app: FastAPI,
    repository: InMemoryRegistrationRepository,
    storage_cipher: LocalSecretBoxCipher,
) -> None:
    async with await _client(app) as client:
        ciphertext = await _sealed_payload(client)
        response = await client.post(
            "/register",
            json={
                "bot_id": "bot-a",
                "server_id": "cts-a",
                "server_host": "https://cts.example.internal",
                "encrypted_secret_key": ciphertext,
            },
        )

    assert response.status_code == 201
    assert response.json() == {"status": "ok", "result": "registered"}
    registration = await repository.get(AccountKey(server_id="cts-a", bot_id="bot-a"))
    assert registration is not None
    assert registration.status is RegistrationStatus.ACTIVE
    assert registration.encrypted_secret is not None
    assert b"very-secret" not in registration.encrypted_secret.ciphertext
    assert await storage_cipher.decrypt(registration.encrypted_secret) == b"very-secret"


@pytest.mark.asyncio
async def test_duplicate_registration_never_replaces_secret(
    app: FastAPI, repository: InMemoryRegistrationRepository
) -> None:
    async with await _client(app) as client:
        first = await _sealed_payload(client, b"first")
        second = await _sealed_payload(client, b"second")
        payload = {
            "bot_id": "bot-a",
            "server_id": "cts-a",
            "server_host": "https://cts.example.internal",
            "encrypted_secret_key": first,
        }
        assert (await client.post("/register", json=payload)).status_code == 201
        before = await repository.get(AccountKey("cts-a", "bot-a"))
        payload["encrypted_secret_key"] = second
        response = await client.post("/register", json=payload)
        after = await repository.get(AccountKey("cts-a", "bot-a"))

    assert response.status_code == 400
    assert response.json()["reason"] == "already_registered"
    assert before is not None and after is not None
    assert after.encrypted_secret == before.encrypted_secret


@pytest.mark.asyncio
async def test_concurrent_first_delivery_has_exactly_one_winner(app: FastAPI) -> None:
    async with await _client(app) as client:
        ciphertext = await _sealed_payload(client)
        payload = {
            "bot_id": "bot-a",
            "server_id": "cts-a",
            "server_host": "https://cts.example.internal",
            "encrypted_secret_key": ciphertext,
        }
        responses = await asyncio.gather(
            *(client.post("/register", json=payload) for _ in range(12))
        )

    assert [response.status_code for response in responses].count(201) == 1
    assert [response.json().get("reason") for response in responses].count(
        "already_registered"
    ) == 11


@pytest.mark.asyncio
async def test_invalid_ciphertext_and_non_allowlisted_endpoint_are_not_persisted(
    app: FastAPI, repository: InMemoryRegistrationRepository
) -> None:
    async with await _client(app) as client:
        response = await client.post(
            "/register",
            json={
                "bot_id": "bot-a",
                "server_id": "cts-a",
                "server_host": "https://public.example",
                "encrypted_secret_key": base64.b64encode(b"x" * 48).decode(),
            },
        )

    assert response.status_code == 400
    assert await repository.get(AccountKey("cts-a", "bot-a")) is None


@pytest.mark.asyncio
async def test_public_key_and_registration_require_the_security_profile(
    service: RegistrationService,
) -> None:
    class RejectingAuthenticator:
        async def authenticate(self, request: Request) -> str:
            raise RegistrationAuthenticationError("untrusted source")

    rejected_app = FastAPI()
    rejected_app.include_router(
        create_registration_router(
            service=service, authenticator=RejectingAuthenticator()
        )
    )
    async with await _client(rejected_app) as client:
        assert (await client.get("/public_key")).status_code == 403
        assert (
            await client.post(
                "/register",
                json={
                    "bot_id": "bot-a",
                    "server_id": "cts-a",
                    "server_host": "https://cts.example.internal",
                    "encrypted_secret_key": "x" * 64,
                },
            )
        ).status_code == 403


@pytest.mark.asyncio
async def test_reset_allows_controlled_reregistration(
    service: RegistrationService, delivery_keys: InMemoryDeliveryKeyProvider
) -> None:
    public_key = PublicKey(await delivery_keys.public_key())

    await service.register(
        RegisterBotCommand(
            bot_id="bot-a",
            server_id="cts-a",
            server_host="https://cts.example.internal",
            encrypted_secret_key=base64.b64encode(SealedBox(public_key).encrypt(b"one")).decode(),
        )
    )
    reset = await service.reset(AccountKey("cts-a", "bot-a"))
    assert reset.status is RegistrationStatus.AWAITING_REGISTRATION
    assert reset.encrypted_secret is None
    active = await service.register(
        RegisterBotCommand(
            bot_id="bot-a",
            server_id="cts-a",
            server_host="https://cts.example.internal",
            encrypted_secret_key=base64.b64encode(SealedBox(public_key).encrypt(b"two")).decode(),
        )
    )
    assert active.status is RegistrationStatus.ACTIVE
