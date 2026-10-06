from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import urlsplit

from nacl.bindings import crypto_box_SEALBYTES

from pybotx_registration.domain import (
    AccountKey,
    InvalidRegistrationRequestError,
    Registration,
)
from pybotx_registration.ports import (
    DeliveryKeyProvider,
    RegistrationRepository,
    SecretCipher,
)


@dataclass(frozen=True, slots=True)
class RegisterBotCommand:
    bot_id: str
    server_id: str
    server_host: str
    encrypted_secret_key: str
    request_id: str | None = None


class HttpsServerHostPolicy:
    """Reject arbitrary URLs before they can become outbound BotX destinations."""

    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        if not allowed_hosts:
            raise ValueError("an explicit CTS host allowlist is required")
        self._allowed_hosts = frozenset(
            host.lower().rstrip(".") for host in allowed_hosts
        )

    def validate(self, server_host: str) -> str:
        parsed = urlsplit(server_host)
        host = parsed.hostname.lower().rstrip(".") if parsed.hostname else None
        try:
            port = parsed.port
        except ValueError as exc:
            raise InvalidRegistrationRequestError(
                "server_host has an invalid port"
            ) from exc
        if (
            parsed.scheme != "https"
            or host is None
            or host not in self._allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise InvalidRegistrationRequestError(
                "server_host violates endpoint policy"
            )
        if port not in (None, 443):
            raise InvalidRegistrationRequestError("server_host port is not allowed")
        return f"https://{host}"


class RegistrationService:
    def __init__(
        self,
        *,
        repository: RegistrationRepository,
        delivery_keys: DeliveryKeyProvider,
        storage_cipher: SecretCipher,
        server_host_policy: HttpsServerHostPolicy,
    ) -> None:
        self._repository = repository
        self._delivery_keys = delivery_keys
        self._storage_cipher = storage_cipher
        self._server_host_policy = server_host_policy

    async def public_key_base64(self) -> str:
        return base64.b64encode(await self._delivery_keys.public_key()).decode("ascii")

    async def register(self, command: RegisterBotCommand) -> Registration:
        key = AccountKey(server_id=command.server_id, bot_id=command.bot_id)
        server_host = self._server_host_policy.validate(command.server_host)
        ciphertext = self._decode_ciphertext(command.encrypted_secret_key)

        # Decrypt only after syntax and endpoint validation. The repository's
        # atomic activate is still authoritative when concurrent requests race.
        plaintext = await self._delivery_keys.decrypt_sealed(ciphertext)
        encrypted_secret = await self._storage_cipher.encrypt(plaintext)
        return await self._repository.activate(
            key=key,
            server_host=server_host,
            encrypted_secret=encrypted_secret,
        )

    async def deactivate(self, key: AccountKey) -> Registration:
        return await self._repository.deactivate(key)

    async def reset(self, key: AccountKey) -> Registration:
        return await self._repository.reset(key)

    @staticmethod
    def _decode_ciphertext(value: str) -> bytes:
        try:
            ciphertext = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise InvalidRegistrationRequestError(
                "encrypted_secret_key is not base64"
            ) from exc
        if len(ciphertext) < crypto_box_SEALBYTES:
            raise InvalidRegistrationRequestError("encrypted_secret_key is too short")
        return ciphertext
