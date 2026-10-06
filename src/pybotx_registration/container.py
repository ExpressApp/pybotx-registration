from dependency_injector import containers, providers

from pybotx_registration.application import HttpsServerHostPolicy, RegistrationService
from pybotx_registration.crypto import InMemoryDeliveryKeyProvider, LocalSecretBoxCipher
from pybotx_registration.repository import InMemoryRegistrationRepository


class RegistrationContainer(containers.DeclarativeContainer):
    """Composition root; replace dev providers, not domain/application code."""

    config = providers.Configuration()
    repository = providers.Singleton(InMemoryRegistrationRepository)
    delivery_keys = providers.Singleton(InMemoryDeliveryKeyProvider.generate)
    storage_cipher = providers.Singleton(
        LocalSecretBoxCipher,
        key=config.storage_key,
        key_id="development",
    )
    server_host_policy = providers.Singleton(
        HttpsServerHostPolicy,
        allowed_hosts=config.allowed_cts_hosts,
    )
    service = providers.Singleton(
        RegistrationService,
        repository=repository,
        delivery_keys=delivery_keys,
        storage_cipher=storage_cipher,
        server_host_policy=server_host_policy,
    )
