from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AccountKey:
    """Stable identity; a BotX bot id alone is deliberately insufficient."""

    server_id: str
    bot_id: str


class RegistrationStatus(StrEnum):
    AWAITING_REGISTRATION = "AWAITING_REGISTRATION"
    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedSecret:
    ciphertext: bytes
    key_id: str


@dataclass(frozen=True, slots=True)
class Registration:
    account_key: AccountKey
    server_host: str
    status: RegistrationStatus
    secret_revision: int
    encrypted_secret: EncryptedSecret | None = field(repr=False)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


class RegistrationError(Exception):
    """Base error whose subclasses never include a secret in their message."""


class AlreadyRegisteredError(RegistrationError):
    pass


class RegistrationNotFoundError(RegistrationError):
    pass


class RegistrationAuthenticationError(RegistrationError):
    pass


class InvalidRegistrationRequestError(RegistrationError):
    pass


class SecretDecryptionError(RegistrationError):
    pass
