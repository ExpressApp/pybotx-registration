from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pytest
from nacl.public import PublicKey, SealedBox

from pybotx_registration.application import (
    HttpsServerHostPolicy,
    RegisterBotCommand,
    RegistrationService,
)
from pybotx_registration.crypto import (
    InMemoryDeliveryKeyProvider,
    LocalSecretBoxCipher,
)
from pybotx_registration.domain import InvalidRegistrationRequestError
from pybotx_registration.pybotx_adapter import (
    PybotxBindings,
    PybotxRegistrationAccountProvider,
    RegistrationAccountSnapshot,
    RegistrationPybotxBridge,
    _normalize_host,
)
from pybotx_registration.repository import InMemoryRegistrationRepository

BOT_ID = UUID("d424de0d-64a5-4de1-b9e0-6c4e88d1a4bf")


@dataclass(frozen=True, slots=True)
class _PybotxAccountKey:
    server_id: str
    bot_id: UUID


@dataclass(frozen=True, slots=True)
class _PybotxAccount:
    id: UUID
    cts_url: str
    secret_key: str
    account_key: _PybotxAccountKey
    revision: int


class _UnknownBotAccountError(Exception):
    pass


class _AmbiguousBotAccountError(Exception):
    pass


@pytest.fixture
def bindings() -> PybotxBindings:
    return PybotxBindings(
        account_key=_PybotxAccountKey,
        account_with_secret=_PybotxAccount,
        unknown_account_error=_UnknownBotAccountError,
        ambiguous_account_error=_AmbiguousBotAccountError,
    )


@pytest.fixture
def multi_cts_service(
    repository: InMemoryRegistrationRepository,
    delivery_keys: InMemoryDeliveryKeyProvider,
    storage_cipher: LocalSecretBoxCipher,
) -> RegistrationService:
    return RegistrationService(
        repository=repository,
        delivery_keys=delivery_keys,
        storage_cipher=storage_cipher,
        server_host_policy=HttpsServerHostPolicy(
            frozenset({"cts-a.example.internal", "cts-b.example.internal"})
        ),
    )


async def _register(
    multi_cts_service: RegistrationService,
    delivery_keys: InMemoryDeliveryKeyProvider,
    *,
    server_id: str,
    server_host: str,
    secret: bytes = b"secret",
    bot_id: UUID = BOT_ID,
) -> None:
    public_key = PublicKey(await delivery_keys.public_key())
    await multi_cts_service.register(
        RegisterBotCommand(
            bot_id=str(bot_id),
            server_id=server_id,
            server_host=server_host,
            encrypted_secret_key=base64.b64encode(
                SealedBox(public_key).encrypt(secret)
            ).decode(),
        )
    )


@pytest.mark.asyncio
async def test__provider__serves_a_refreshed_snapshot_without_database_io(
    multi_cts_service: RegistrationService,
    delivery_keys: InMemoryDeliveryKeyProvider,
    bindings: PybotxBindings,
) -> None:
    await _register(
        multi_cts_service,
        delivery_keys,
        server_id="cts-a",
        server_host="https://cts-a.example.internal",
    )
    snapshot = RegistrationAccountSnapshot()
    await snapshot.refresh(multi_cts_service)
    provider = PybotxRegistrationAccountProvider(snapshot, bindings=bindings)

    account = provider.get_account(_PybotxAccountKey("cts-a", BOT_ID))
    incoming_key = provider.resolve_incoming_account_key(
        bot_id=BOT_ID,
        host="https://CTS-A.EXAMPLE.INTERNAL:443/",
    )

    assert account == _PybotxAccount(
        id=BOT_ID,
        cts_url="https://cts-a.example.internal",
        secret_key="secret",
        account_key=_PybotxAccountKey("cts-a", BOT_ID),
        revision=1,
    )
    assert incoming_key == _PybotxAccountKey("cts-a", BOT_ID)
    assert tuple(provider.iter_bot_accounts()) == (account,)


@pytest.mark.asyncio
async def test__provider__resolves_multi_cts_and_rejects_ambiguous_bot_ids(
    multi_cts_service: RegistrationService,
    delivery_keys: InMemoryDeliveryKeyProvider,
    bindings: PybotxBindings,
) -> None:
    await _register(
        multi_cts_service,
        delivery_keys,
        server_id="cts-a",
        server_host="https://cts-a.example.internal",
        secret=b"one",
    )
    await _register(
        multi_cts_service,
        delivery_keys,
        server_id="cts-b",
        server_host="https://cts-b.example.internal",
        secret=b"two",
    )
    snapshot = RegistrationAccountSnapshot()
    await snapshot.refresh(multi_cts_service)
    provider = PybotxRegistrationAccountProvider(snapshot, bindings=bindings)

    cts_b_key = provider.resolve_incoming_account_key(
        bot_id=BOT_ID,
        host="cts-b.example.internal",
    )

    assert cts_b_key == _PybotxAccountKey("cts-b", BOT_ID)
    cts_b_account = provider.get_account(cts_b_key)
    assert isinstance(cts_b_account, _PybotxAccount)
    assert cts_b_account.secret_key == "two"
    with pytest.raises(_AmbiguousBotAccountError):
        provider.get_account_by_bot_id(BOT_ID)
    with pytest.raises(_AmbiguousBotAccountError):
        provider.resolve_incoming_account_key(bot_id=BOT_ID, host=None)


@pytest.mark.asyncio
async def test__bridge__refreshes_snapshot_and_invalidates_after_all_lifecycle_changes(
    multi_cts_service: RegistrationService,
    delivery_keys: InMemoryDeliveryKeyProvider,
    bindings: PybotxBindings,
) -> None:
    invalidated: list[_PybotxAccountKey] = []
    snapshot = RegistrationAccountSnapshot()
    provider = PybotxRegistrationAccountProvider(snapshot, bindings=bindings)
    provider.bind_invalidator(
        lambda account: invalidated.append(
            cast(_PybotxAccountKey, account)
        )
    )
    bridge = RegistrationPybotxBridge(
        service=multi_cts_service,
        snapshot=snapshot,
        provider=provider,
    )
    public_key = PublicKey(await delivery_keys.public_key())
    command = RegisterBotCommand(
        bot_id=str(BOT_ID),
        server_id="cts-a",
        server_host="https://cts-a.example.internal",
        encrypted_secret_key=base64.b64encode(
            SealedBox(public_key).encrypt(b"one")
        ).decode(),
    )

    await bridge.startup()
    created = await bridge.register(command)
    reset = await bridge.reset(created.account_key)
    reregistered = await bridge.register(command)
    deactivated = await bridge.deactivate(reregistered.account_key)

    assert reset.account_key == created.account_key
    assert deactivated.account_key == created.account_key
    assert invalidated == [_PybotxAccountKey("cts-a", BOT_ID)] * 4
    with pytest.raises(_UnknownBotAccountError):
        provider.get_account(_PybotxAccountKey("cts-a", BOT_ID))


@pytest.mark.asyncio
async def test__bridge__rejects_non_uuid_bot_id_before_persisting(
    service: RegistrationService,
    repository: InMemoryRegistrationRepository,
    bindings: PybotxBindings,
) -> None:
    snapshot = RegistrationAccountSnapshot()
    provider = PybotxRegistrationAccountProvider(snapshot, bindings=bindings)
    bridge = RegistrationPybotxBridge(
        service=service,
        snapshot=snapshot,
        provider=provider,
    )

    with pytest.raises(InvalidRegistrationRequestError, match="UUID"):
        await bridge.register(
            RegisterBotCommand(
                bot_id="not-a-uuid",
                server_id="cts-a",
                server_host="https://cts-a.example.internal",
                encrypted_secret_key="x" * 64,
            )
        )

    assert await repository.list_active() == ()


def test__normalize_host__rejects_invalid_or_unsupported_hosts() -> None:
    assert _normalize_host("CTS.EXAMPLE.INTERNAL.") == "cts.example.internal"
    for host in ("https://cts.example.internal:8443", "https://:443"):
        with pytest.raises(ValueError):
            _normalize_host(host)
