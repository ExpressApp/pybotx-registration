from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from pybotx_registration.application import RegisterBotCommand, RegistrationService
from pybotx_registration.domain import (
    AccountKey,
    ActiveBotCredential,
    AlreadyRegisteredError,
    InvalidRegistrationRequestError,
    Registration,
)


@dataclass(frozen=True, slots=True)
class _SnapshotAccount:
    account_key: AccountKey
    bot_id: UUID
    cts_url: str
    secret_key: str = field(repr=False)
    revision: int
    host: str


@dataclass(frozen=True, slots=True)
class PybotxBindings:
    """Runtime pybotx constructors, injectable to test without a released SDK."""

    account_key: Callable[[str, UUID], object]
    account_with_secret: Callable[..., object]
    unknown_account_error: Callable[[UUID], Exception]
    ambiguous_account_error: Callable[[UUID], Exception]


class RegistrationAccountSnapshot:
    """Read-only in-process snapshot; synchronous lookups never access PostgreSQL."""

    def __init__(self) -> None:
        self._accounts: Mapping[AccountKey, _SnapshotAccount] = MappingProxyType({})
        self._keys_by_bot_id: Mapping[UUID, tuple[AccountKey, ...]] = MappingProxyType(
            {}
        )
        self._keys_by_host: Mapping[tuple[str, UUID], AccountKey] = MappingProxyType({})
        self._refresh_lock = asyncio.Lock()

    async def refresh(self, service: RegistrationService) -> None:
        """Build a complete replacement snapshot before atomically publishing it."""
        async with self._refresh_lock:
            credentials = await service.active_credentials()
            accounts = self._build_accounts(credentials)
            by_bot_id: dict[UUID, list[AccountKey]] = {}
            by_host: dict[tuple[str, UUID], AccountKey] = {}
            for account in accounts.values():
                by_bot_id.setdefault(account.bot_id, []).append(account.account_key)
                host_key = (account.host, account.bot_id)
                if host_key in by_host:
                    raise ValueError(
                        "multiple active registrations have the same CTS host and "
                        "bot id"
                    )
                by_host[host_key] = account.account_key
            self._accounts = MappingProxyType(accounts)
            self._keys_by_bot_id = MappingProxyType(
                {bot_id: tuple(keys) for bot_id, keys in by_bot_id.items()}
            )
            self._keys_by_host = MappingProxyType(by_host)

    def get(self, account_key: AccountKey) -> _SnapshotAccount:
        return self._accounts[account_key]

    def get_by_bot_id(self, bot_id: UUID) -> _SnapshotAccount:
        keys = self._keys_by_bot_id.get(bot_id, ())
        if not keys:
            raise KeyError(bot_id)
        if len(keys) > 1:
            raise LookupError(bot_id)
        return self.get(keys[0])

    def resolve_incoming(self, *, bot_id: UUID, host: str | None) -> AccountKey:
        if host is None:
            return self.get_by_bot_id(bot_id).account_key
        return self._keys_by_host[(_normalize_host(host), bot_id)]

    def iter_accounts(self) -> Iterator[_SnapshotAccount]:
        yield from self._accounts.values()

    @staticmethod
    def _build_accounts(
        credentials: tuple[ActiveBotCredential, ...],
    ) -> dict[AccountKey, _SnapshotAccount]:
        accounts: dict[AccountKey, _SnapshotAccount] = {}
        for credential in credentials:
            try:
                bot_id = UUID(credential.account_key.bot_id)
            except ValueError as exc:
                raise ValueError(
                    "active registration bot_id must be a UUID for pybotx"
                ) from exc
            accounts[credential.account_key] = _SnapshotAccount(
                account_key=credential.account_key,
                bot_id=bot_id,
                cts_url=credential.server_host,
                secret_key=credential.secret_key,
                revision=credential.secret_revision,
                host=_normalize_host(credential.server_host),
            )
        return accounts


class PybotxRegistrationAccountProvider:
    """Duck-typed implementation of pybotx's synchronous account-provider port."""

    def __init__(
        self,
        snapshot: RegistrationAccountSnapshot,
        *,
        invalidate_account: Callable[[object], None] | None = None,
        bindings: PybotxBindings | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._bindings = bindings or _load_pybotx_bindings()
        self._invalidate_account = invalidate_account

    def get_account(self, key: Any) -> object:
        account_key = AccountKey(server_id=str(key.server_id), bot_id=str(key.bot_id))
        try:
            account = self._snapshot.get(account_key)
        except KeyError as exc:
            raise self._bindings.unknown_account_error(key.bot_id) from exc
        return self._to_pybotx_account(account)

    def get_account_by_bot_id(self, bot_id: UUID) -> object:
        keys = tuple(
            account.account_key
            for account in self._snapshot.iter_accounts()
            if account.bot_id == bot_id
        )
        if not keys:
            raise self._bindings.unknown_account_error(bot_id)
        if len(keys) > 1:
            raise self._bindings.ambiguous_account_error(bot_id)
        return self._to_pybotx_account(self._snapshot.get(keys[0]))

    def resolve_incoming_account_key(self, *, bot_id: UUID, host: str | None) -> object:
        try:
            account_key = self._snapshot.resolve_incoming(bot_id=bot_id, host=host)
        except KeyError as exc:
            raise self._bindings.unknown_account_error(bot_id) from exc
        except LookupError as exc:
            raise self._bindings.ambiguous_account_error(bot_id) from exc
        return self._bindings.account_key(account_key.server_id, bot_id)

    def iter_bot_accounts(self) -> Iterator[object]:
        for account in self._snapshot.iter_accounts():
            yield self._to_pybotx_account(account)

    def invalidate(self, account_key: AccountKey) -> None:
        if self._invalidate_account is not None:
            self._invalidate_account(
                self._bindings.account_key(
                    account_key.server_id,
                    UUID(account_key.bot_id),
                )
            )

    def bind_invalidator(self, callback: Callable[[object], None]) -> None:
        """Attach ``Bot.invalidate_account`` after the Bot instance is created."""
        self._invalidate_account = callback

    def _to_pybotx_account(self, account: _SnapshotAccount) -> object:
        return self._bindings.account_with_secret(
            id=account.bot_id,
            cts_url=account.cts_url,
            secret_key=account.secret_key,
            account_key=self._bindings.account_key(
                account.account_key.server_id, account.bot_id
            ),
            revision=account.revision,
        )


class RegistrationPybotxBridge:
    """Keeps the pybotx snapshot and its JWT cache in sync with lifecycle writes."""

    def __init__(
        self,
        *,
        service: RegistrationService,
        snapshot: RegistrationAccountSnapshot,
        provider: PybotxRegistrationAccountProvider,
    ) -> None:
        self._service = service
        self._snapshot = snapshot
        self._provider = provider

    async def startup(self) -> None:
        await self._snapshot.refresh(self._service)

    async def public_key_base64(self) -> str:
        return await self._service.public_key_base64()

    async def register(self, command: RegisterBotCommand) -> Registration:
        try:
            UUID(command.bot_id)
        except ValueError as exc:
            raise InvalidRegistrationRequestError(
                "bot_id must be a UUID for pybotx"
            ) from exc
        try:
            registration = await self._service.register(command)
        except AlreadyRegisteredError:
            await self.startup()
            raise
        await self._after_change(registration)
        return registration

    async def deactivate(self, key: AccountKey) -> Registration:
        registration = await self._service.deactivate(key)
        await self._after_change(registration)
        return registration

    async def reset(self, key: AccountKey) -> Registration:
        registration = await self._service.reset(key)
        await self._after_change(registration)
        return registration

    async def _after_change(self, registration: Registration) -> None:
        self._provider.invalidate(registration.account_key)
        await self.startup()


def _normalize_host(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.hostname is None:
        raise ValueError("CTS host is missing")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("CTS host has an invalid port") from exc
    if port not in (None, 443):
        raise ValueError("CTS host port is not supported")
    return parsed.hostname.lower().rstrip(".")


def _load_pybotx_bindings() -> PybotxBindings:
    try:
        pybotx_module = importlib.import_module("pybotx")
        exceptions_module = importlib.import_module("pybotx.bot.exceptions")
        bot_account_key = vars(pybotx_module)["BotAccountKey"]
        bot_account_with_secret = vars(pybotx_module)["BotAccountWithSecret"]
        unknown_account_error = vars(pybotx_module)["UnknownBotAccountError"]
        ambiguous_account_error = vars(exceptions_module)["AmbiguousBotAccountError"]
    except (ImportError, KeyError) as exc:
        raise RuntimeError(
            "pybotx with the dynamic account-provider API from PR #557 is required"
        ) from exc
    return PybotxBindings(
        account_key=bot_account_key,
        account_with_secret=bot_account_with_secret,
        unknown_account_error=unknown_account_error,
        ambiguous_account_error=ambiguous_account_error,
    )
