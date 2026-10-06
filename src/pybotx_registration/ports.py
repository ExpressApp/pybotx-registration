from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

from starlette.requests import Request

from pybotx_registration.domain import AccountKey, EncryptedSecret, Registration

if TYPE_CHECKING:
    from pybotx_registration.application import RegisterBotCommand


class DeliveryKeyProvider(Protocol):
    async def public_key(self) -> bytes: ...

    async def decrypt_sealed(self, ciphertext: bytes) -> bytes: ...


class SecretCipher(Protocol):
    async def encrypt(self, plaintext: bytes) -> EncryptedSecret: ...

    async def decrypt(self, encrypted: EncryptedSecret) -> bytes: ...


class RegistrationRepository(Protocol):
    async def get(self, key: AccountKey) -> Registration | None: ...

    async def activate(
        self,
        *,
        key: AccountKey,
        server_host: str,
        encrypted_secret: EncryptedSecret,
    ) -> Registration: ...

    async def deactivate(self, key: AccountKey) -> Registration: ...

    async def reset(self, key: AccountKey) -> Registration: ...

    async def list_active(self) -> Sequence[Registration]: ...


class RegistrationCommandHandler(Protocol):
    async def register(self, command: RegisterBotCommand) -> Registration: ...


class RegistrationHttpService(RegistrationCommandHandler, Protocol):
    async def public_key_base64(self) -> str: ...


class RegistrationAuthenticator(Protocol):
    async def authenticate(self, request: Request) -> str:
        """Return an audit principal or raise RegistrationAuthenticationError."""
