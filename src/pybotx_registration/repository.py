from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    LargeBinary,
    MetaData,
    String,
    Table,
    and_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql.elements import ColumnElement

from pybotx_registration.domain import (
    AccountKey,
    AlreadyRegisteredError,
    EncryptedSecret,
    Registration,
    RegistrationNotFoundError,
    RegistrationStatus,
    SecretDecryptionError,
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

    async def list_active(self) -> Sequence[Registration]:
        async with self._lock:
            return tuple(
                registration
                for registration in self._registrations.values()
                if registration.status is RegistrationStatus.ACTIVE
            )

    def _required(self, key: AccountKey) -> Registration:
        registration = self._registrations.get(key)
        if registration is None:
            raise RegistrationNotFoundError(f"registration is absent: {key.server_id}")
        return registration


metadata = MetaData()
registrations = Table(
    "botx_registrations",
    metadata,
    Column("server_id", String(256), primary_key=True),
    Column("bot_id", String(256), primary_key=True),
    Column("server_host", String(2048), nullable=False),
    Column("status", String(32), nullable=False),
    Column("secret_revision", BigInteger, nullable=False),
    Column("storage_ciphertext", LargeBinary, nullable=True),
    Column("storage_key_id", String(256), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("secret_revision > 0", name="ck_botx_registrations_revision"),
    CheckConstraint(
        "status IN ('AWAITING_REGISTRATION', 'ACTIVE', 'DEACTIVATED')",
        name="ck_botx_registrations_status",
    ),
    CheckConstraint(
        "status <> 'ACTIVE' OR "
        "(storage_ciphertext IS NOT NULL AND storage_key_id IS NOT NULL)",
        name="ck_botx_registrations_active_secret",
    ),
)

key_material = Table(
    "botx_key_material",
    metadata,
    Column("name", String(128), primary_key=True),
    Column("root_key_id", String(128), nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


class PostgresRegistrationRepository:
    """Durable registration repository with transaction-safe lifecycle updates."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def get(self, key: AccountKey) -> Registration | None:
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(registrations).where(_key_clause(key))
            )
            row = result.mappings().one_or_none()
        return _to_registration(row) if row is not None else None

    async def activate(
        self,
        *,
        key: AccountKey,
        server_host: str,
        encrypted_secret: EncryptedSecret,
    ) -> Registration:
        now = utc_now()
        async with self._engine.begin() as connection:
            insert_result = await connection.execute(
                insert(registrations)
                .values(
                    server_id=key.server_id,
                    bot_id=key.bot_id,
                    server_host=server_host,
                    status=RegistrationStatus.ACTIVE.value,
                    secret_revision=1,
                    storage_ciphertext=encrypted_secret.ciphertext,
                    storage_key_id=encrypted_secret.key_id,
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["server_id", "bot_id"])
                .returning(registrations)
            )
            inserted = insert_result.mappings().one_or_none()
            if inserted is not None:
                return _to_registration(inserted)

            existing = await self._get_for_update(connection, key)
            if existing.status is not RegistrationStatus.AWAITING_REGISTRATION:
                raise AlreadyRegisteredError("credential already exists")

            update_result = await connection.execute(
                update(registrations)
                .where(_key_clause(key))
                .values(
                    server_host=server_host,
                    status=RegistrationStatus.ACTIVE.value,
                    secret_revision=existing.secret_revision + 1,
                    storage_ciphertext=encrypted_secret.ciphertext,
                    storage_key_id=encrypted_secret.key_id,
                    updated_at=now,
                )
                .returning(registrations)
            )
            return _to_registration(update_result.mappings().one())

    async def deactivate(self, key: AccountKey) -> Registration:
        async with self._engine.begin() as connection:
            existing = await self._get_for_update(connection, key)
            if existing.status is RegistrationStatus.DEACTIVATED:
                return existing
            result = await connection.execute(
                update(registrations)
                .where(_key_clause(key))
                .values(
                    status=RegistrationStatus.DEACTIVATED.value,
                    updated_at=utc_now(),
                )
                .returning(registrations)
            )
            return _to_registration(result.mappings().one())

    async def reset(self, key: AccountKey) -> Registration:
        async with self._engine.begin() as connection:
            existing = await self._get_for_update(connection, key)
            result = await connection.execute(
                update(registrations)
                .where(_key_clause(key))
                .values(
                    status=RegistrationStatus.AWAITING_REGISTRATION.value,
                    secret_revision=existing.secret_revision + 1,
                    storage_ciphertext=None,
                    storage_key_id=None,
                    updated_at=utc_now(),
                )
                .returning(registrations)
            )
            return _to_registration(result.mappings().one())

    async def list_active(self) -> Sequence[Registration]:
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(registrations)
                .where(
                    registrations.c.status == RegistrationStatus.ACTIVE.value,
                )
                .order_by(registrations.c.server_id, registrations.c.bot_id)
            )
            rows = result.mappings().all()
        return tuple(_to_registration(row) for row in rows)

    async def _get_for_update(
        self,
        connection: AsyncConnection,
        key: AccountKey,
    ) -> Registration:
        result = await connection.execute(
            select(registrations).where(_key_clause(key)).with_for_update()
        )
        row = result.mappings().one_or_none()
        if row is None:
            raise RegistrationNotFoundError(f"registration is absent: {key.server_id}")
        return _to_registration(row)


class PostgresKeyMaterialRepository:
    """Stores service keys in PostgreSQL encrypted by the bot-local root key."""

    def __init__(self, engine: AsyncEngine, root_key: bytes) -> None:
        if len(root_key) != SecretBox.KEY_SIZE:
            raise ValueError(f"root key must be {SecretBox.KEY_SIZE} bytes")
        self._engine = engine
        self._box = SecretBox(root_key)
        self._root_key_id = f"local-root:{hashlib.sha256(root_key).hexdigest()}"

    async def get_or_create(self, name: str, *, size: int) -> bytes:
        if not name or size <= 0:
            raise ValueError("key material name and size must be positive")
        value = os.urandom(size)
        now = utc_now()
        async with self._engine.begin() as connection:
            inserted = await connection.execute(
                insert(key_material)
                .values(
                    name=name,
                    root_key_id=self._root_key_id,
                    ciphertext=bytes(self._box.encrypt(value)),
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["name"])
                .returning(key_material.c.name)
            )
            if inserted.mappings().one_or_none() is not None:
                return value

            result = await connection.execute(
                select(key_material)
                .where(key_material.c.name == name)
                .with_for_update()
            )
            row = result.mappings().one_or_none()
            if row is None:
                raise RuntimeError(
                    f"key material disappeared during initialization: {name}"
                )
            if row["root_key_id"] != self._root_key_id:
                raise SecretDecryptionError(
                    "local root key does not match stored key material"
                )
            try:
                key = self._box.decrypt(row["ciphertext"])
            except CryptoError as exc:
                raise SecretDecryptionError(
                    "stored key material cannot be decrypted"
                ) from exc
            if len(key) != size:
                raise SecretDecryptionError(
                    "stored key material has an unexpected size"
                )
            return key


def _key_clause(key: AccountKey) -> ColumnElement[bool]:
    return and_(
        registrations.c.server_id == key.server_id,
        registrations.c.bot_id == key.bot_id,
    )


def _to_registration(row: RowMapping) -> Registration:
    ciphertext = row["storage_ciphertext"]
    key_id = row["storage_key_id"]
    encrypted_secret = (
        EncryptedSecret(ciphertext=bytes(ciphertext), key_id=key_id)
        if ciphertext is not None and key_id is not None
        else None
    )
    return Registration(
        account_key=AccountKey(server_id=row["server_id"], bot_id=row["bot_id"]),
        server_host=row["server_host"],
        status=RegistrationStatus(row["status"]),
        secret_revision=int(row["secret_revision"]),
        encrypted_secret=encrypted_secret,
        created_at=_as_datetime(row["created_at"]),
        updated_at=_as_datetime(row["updated_at"]),
    )


def _as_datetime(value: object) -> datetime:
    assert isinstance(value, datetime)
    return value
