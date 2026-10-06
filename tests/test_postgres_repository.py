from __future__ import annotations

import hashlib
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import cast

import pytest
from nacl.secret import SecretBox
from sqlalchemy.ext.asyncio import AsyncEngine

from pybotx_registration.domain import (
    AccountKey,
    AlreadyRegisteredError,
    EncryptedSecret,
    RegistrationNotFoundError,
    RegistrationStatus,
    SecretDecryptionError,
)
from pybotx_registration.repository import (
    PostgresKeyMaterialRepository,
    PostgresRegistrationRepository,
)


class _Mappings:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def one_or_none(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None

    def one(self) -> dict[str, object]:
        assert self._rows
        return self._rows[0]

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Result:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._mappings = _Mappings(rows)

    def mappings(self) -> _Mappings:
        return self._mappings


class _Connection:
    def __init__(self, results: list[list[dict[str, object]]]) -> None:
        self._results = results

    async def execute(self, _: object) -> _Result:
        assert self._results
        return _Result(self._results.pop(0))


class _ConnectionContext(AbstractAsyncContextManager[_Connection]):
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    async def __aenter__(self) -> _Connection:
        return self._connection

    async def __aexit__(self, *args: object) -> None:
        return None


class _Engine:
    def __init__(self, results: list[list[dict[str, object]]]) -> None:
        self._connection = _Connection(results)

    def connect(self) -> _ConnectionContext:
        return _ConnectionContext(self._connection)

    def begin(self) -> _ConnectionContext:
        return _ConnectionContext(self._connection)


def _row(
    *,
    status: RegistrationStatus = RegistrationStatus.ACTIVE,
    revision: int = 1,
    ciphertext: bytes | None = b"ciphertext",
    key_id: str | None = "postgres-key-material:v1",
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "server_id": "cts-a",
        "bot_id": "bot-a",
        "server_host": "https://cts-a.example.internal",
        "status": status.value,
        "secret_revision": revision,
        "storage_ciphertext": ciphertext,
        "storage_key_id": key_id,
        "created_at": now,
        "updated_at": now,
    }


def _repository(*results: list[dict[str, object]]) -> PostgresRegistrationRepository:
    return PostgresRegistrationRepository(cast(AsyncEngine, _Engine(list(results))))


def _key_material_repository(
    root_key: bytes,
    *results: list[dict[str, object]],
) -> PostgresKeyMaterialRepository:
    return PostgresKeyMaterialRepository(
        cast(AsyncEngine, _Engine(list(results))), root_key
    )


@pytest.mark.asyncio
async def test__postgres_repository__maps_durable_rows_and_active_snapshots() -> None:
    repository = _repository(
        [_row()],
        [_row(), _row(status=RegistrationStatus.DEACTIVATED)],
    )

    registration = await repository.get(AccountKey("cts-a", "bot-a"))
    active = await repository.list_active()

    assert registration is not None
    assert registration.encrypted_secret == EncryptedSecret(
        ciphertext=b"ciphertext", key_id="postgres-key-material:v1"
    )
    assert len(active) == 2


@pytest.mark.asyncio
async def test__postgres_repository__activates_or_rejects_existing_credentials(
) -> None:
    key = AccountKey("cts-a", "bot-a")
    secret = EncryptedSecret(ciphertext=b"next", key_id="postgres-key-material:v1")

    created = await _repository([_row()]).activate(
        key=key,
        server_host="https://cts-a.example.internal",
        encrypted_secret=secret,
    )
    restored = await _repository(
        [],
        [
            _row(
                status=RegistrationStatus.AWAITING_REGISTRATION,
                revision=2,
                ciphertext=None,
                key_id=None,
            )
        ],
        [_row(revision=3)],
    ).activate(
        key=key,
        server_host="https://cts-a.example.internal",
        encrypted_secret=secret,
    )

    assert created.secret_revision == 1
    assert restored.secret_revision == 3

    with pytest.raises(AlreadyRegisteredError):
        await _repository([], [_row()]).activate(
            key=key,
            server_host="https://cts-a.example.internal",
            encrypted_secret=secret,
        )


@pytest.mark.asyncio
async def test__postgres_repository__transitions_lifecycle_or_reports_missing() -> None:
    key = AccountKey("cts-a", "bot-a")
    deactivated_repository = _repository(
        [_row()],
        [_row(status=RegistrationStatus.DEACTIVATED)],
    )
    reset_repository = _repository(
        [_row()],
        [
            _row(
                status=RegistrationStatus.AWAITING_REGISTRATION,
                revision=2,
                ciphertext=None,
                key_id=None,
            )
        ],
    )

    deactivated = await deactivated_repository.deactivate(key)
    reset = await reset_repository.reset(key)

    assert deactivated.status is RegistrationStatus.DEACTIVATED
    assert reset.encrypted_secret is None

    with pytest.raises(RegistrationNotFoundError):
        await _repository([]).reset(key)


@pytest.mark.asyncio
async def test__postgres_key_material__restores_db_encrypted_key_after_restart(
) -> None:
    root_key = b"r" * SecretBox.KEY_SIZE
    stored_key = b"s" * SecretBox.KEY_SIZE
    ciphertext = bytes(SecretBox(root_key).encrypt(stored_key))
    repository = _key_material_repository(
        root_key,
        [],
        [
            {
                "name": "storage_secretbox_key_v1",
                "root_key_id": f"local-root:{hashlib.sha256(root_key).hexdigest()}",
                "ciphertext": ciphertext,
            }
        ],
    )

    restored_key = await repository.get_or_create(
        "storage_secretbox_key_v1", size=SecretBox.KEY_SIZE
    )

    assert restored_key == stored_key


@pytest.mark.asyncio
async def test__postgres_key_material__creates_or_rejects_unreadable_material() -> None:
    root_key = b"r" * SecretBox.KEY_SIZE
    created = await _key_material_repository(
        root_key, [{"name": "delivery_private_key_v1"}]
    ).get_or_create("delivery_private_key_v1", size=32)

    with pytest.raises(SecretDecryptionError, match="does not match"):
        await _key_material_repository(
            b"x" * SecretBox.KEY_SIZE,
            [],
            [
                {
                    "name": "delivery_private_key_v1",
                    "root_key_id": "local-root:another-root",
                    "ciphertext": b"unreadable",
                }
            ],
        ).get_or_create("delivery_private_key_v1", size=32)

    assert len(created) == 32
