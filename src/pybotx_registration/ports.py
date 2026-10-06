from __future__ import annotations

from typing import Protocol

from starlette.requests import Request

from pybotx_registration.domain import AccountKey, EncryptedSecret, Registration


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


class RegistrationAuthenticator(Protocol):
    async def authenticate(self, request: Request) -> str:
        """Return an audit principal or raise RegistrationAuthenticationError."""
