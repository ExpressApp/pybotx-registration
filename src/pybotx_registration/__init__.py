"""Secure BotX registration protocol primitives and FastAPI adapter."""

from pybotx_registration.application import RegistrationService
from pybotx_registration.auth import AllowlistedPeerAuthenticator
from pybotx_registration.container import (
    RegistrationContainer,
    RegistrationRuntime,
    initialize_registration_runtime,
)
from pybotx_registration.crypto import (
    InMemoryDeliveryKeyProvider,
    LocalKeyStore,
    LocalSecretBoxCipher,
)
from pybotx_registration.domain import (
    AccountKey,
    ActiveBotCredential,
    RegistrationStatus,
)
from pybotx_registration.presentation import create_registration_router
from pybotx_registration.pybotx_adapter import (
    PybotxRegistrationAccountProvider,
    RegistrationAccountSnapshot,
    RegistrationPybotxBridge,
)
from pybotx_registration.repository import (
    InMemoryRegistrationRepository,
    PostgresKeyMaterialRepository,
    PostgresRegistrationRepository,
)

__all__ = [
    "AccountKey",
    "ActiveBotCredential",
    "AllowlistedPeerAuthenticator",
    "InMemoryDeliveryKeyProvider",
    "InMemoryRegistrationRepository",
    "LocalSecretBoxCipher",
    "LocalKeyStore",
    "PostgresRegistrationRepository",
    "PostgresKeyMaterialRepository",
    "PybotxRegistrationAccountProvider",
    "RegistrationAccountSnapshot",
    "RegistrationContainer",
    "RegistrationRuntime",
    "RegistrationService",
    "RegistrationStatus",
    "RegistrationPybotxBridge",
    "create_registration_router",
    "initialize_registration_runtime",
]
