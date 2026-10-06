from dataclasses import dataclass

from dependency_injector import containers, providers
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pybotx_registration.application import HttpsServerHostPolicy, RegistrationService
from pybotx_registration.crypto import (
    InMemoryDeliveryKeyProvider,
    LocalKeyStore,
    LocalSecretBoxCipher,
)
from pybotx_registration.repository import (
    PostgresKeyMaterialRepository,
    PostgresRegistrationRepository,
)


def create_postgres_engine(postgres_dsn: str) -> AsyncEngine:
    return create_async_engine(postgres_dsn, pool_pre_ping=True)


class RegistrationContainer(containers.DeclarativeContainer):
    """Production composition root for durable data and encrypted key material."""

    config = providers.Configuration()
    engine = providers.Singleton(
        create_postgres_engine,
        postgres_dsn=config.postgres_dsn,
    )
    repository = providers.Singleton(PostgresRegistrationRepository, engine=engine)
    key_store = providers.Singleton(LocalKeyStore, directory=config.key_directory)
    root_key = providers.Singleton(
        lambda store: store.get_or_create("root_key", size=SecretBox.KEY_SIZE),
        store=key_store,
    )
    key_material = providers.Singleton(
        PostgresKeyMaterialRepository,
        engine=engine,
        root_key=root_key,
    )
    server_host_policy = providers.Singleton(
        HttpsServerHostPolicy,
        allowed_hosts=config.allowed_cts_hosts,
    )


async def build_registration_service(
    container: RegistrationContainer,
) -> RegistrationService:
    """Load durable service keys before exposing the registration router."""
    key_material = container.key_material()
    delivery_private_key = await key_material.get_or_create(
        "delivery_private_key_v1",
        size=PrivateKey.SIZE,
    )
    storage_key = await key_material.get_or_create(
        "storage_secretbox_key_v1",
        size=SecretBox.KEY_SIZE,
    )
    storage_key_id = "postgres-key-material:v1"
    return RegistrationService(
        repository=container.repository(),
        delivery_keys=InMemoryDeliveryKeyProvider(PrivateKey(delivery_private_key)),
        storage_cipher=LocalSecretBoxCipher(storage_key, key_id=storage_key_id),
        server_host_policy=container.server_host_policy(),
    )


@dataclass(frozen=True, slots=True)
class RegistrationRuntime:
    """Ready-to-serve registration dependencies with explicit resource cleanup."""

    service: RegistrationService
    engine: AsyncEngine

    async def shutdown(self) -> None:
        await self.engine.dispose()


async def initialize_registration_runtime(
    container: RegistrationContainer,
) -> RegistrationRuntime:
    """Fail startup before serving if persisted credentials cannot be decrypted."""
    service = await build_registration_service(container)
    await service.verify_durable_credentials()
    return RegistrationRuntime(service=service, engine=container.engine())
