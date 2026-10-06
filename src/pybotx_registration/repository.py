from __future__ import annotations

import asyncio
from dataclasses import replace

from pybotx_registration.domain import (
    AccountKey,
    AlreadyRegisteredError,
    EncryptedSecret,
    Registration,
    RegistrationNotFoundError,
    RegistrationStatus,
    utc_now,
)


class InMemoryRegistrationRepository:
    """Concurrency-correct test adapter; production uses a DB unique constraint."""

    def __init__(self) -> None:
        self._registrations: dict[AccountKey, Registration] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: AccountKey) -> Registration | None:
        async with self._lock:
            return self._registrations.get(key)

    async def activate(
        self,
        *,
        key: AccountKey,
        server_host: str,
        encrypted_secret: EncryptedSecret,
    ) -> Registration:
        async with self._lock:
            existing = self._registrations.get(key)
            if existing is None:
                registration = Registration(
                    account_key=key,
                    server_host=server_host,
                    status=RegistrationStatus.ACTIVE,
                    secret_revision=1,
                    encrypted_secret=encrypted_secret,
                )
            elif existing.status is RegistrationStatus.AWAITING_REGISTRATION:
                registration = replace(
                    existing,
                    server_host=server_host,
                    status=RegistrationStatus.ACTIVE,
                    secret_revision=existing.secret_revision + 1,
                    encrypted_secret=encrypted_secret,
                    updated_at=utc_now(),
                )
            else:
                raise AlreadyRegisteredError("credential already exists")
            self._registrations[key] = registration
            return registration

    async def deactivate(self, key: AccountKey) -> Registration:
        async with self._lock:
            registration = self._required(key)
            if registration.status is RegistrationStatus.DEACTIVATED:
                return registration
            registration = replace(
                registration,
                status=RegistrationStatus.DEACTIVATED,
                updated_at=utc_now(),
            )
            self._registrations[key] = registration
            return registration

    async def reset(self, key: AccountKey) -> Registration:
        async with self._lock:
            registration = self._required(key)
            registration = replace(
                registration,
                status=RegistrationStatus.AWAITING_REGISTRATION,
                secret_revision=registration.secret_revision + 1,
                encrypted_secret=None,
                updated_at=utc_now(),
            )
            self._registrations[key] = registration
            return registration

    def _required(self, key: AccountKey) -> Registration:
        registration = self._registrations.get(key)
        if registration is None:
            raise RegistrationNotFoundError(f"registration is absent: {key.server_id}")
        return registration
