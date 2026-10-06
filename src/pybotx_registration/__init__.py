"""Secure BotX registration protocol primitives and FastAPI adapter."""

from pybotx_registration.application import RegistrationService
from pybotx_registration.auth import AllowlistedPeerAuthenticator
from pybotx_registration.crypto import InMemoryDeliveryKeyProvider, LocalSecretBoxCipher
from pybotx_registration.domain import AccountKey, RegistrationStatus
from pybotx_registration.presentation import create_registration_router
from pybotx_registration.repository import InMemoryRegistrationRepository

__all__ = [
    "AccountKey",
    "AllowlistedPeerAuthenticator",
    "InMemoryDeliveryKeyProvider",
    "InMemoryRegistrationRepository",
    "LocalSecretBoxCipher",
    "RegistrationService",
    "RegistrationStatus",
    "create_registration_router",
]
