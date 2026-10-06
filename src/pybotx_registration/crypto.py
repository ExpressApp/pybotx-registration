from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox
from nacl.secret import SecretBox

from pybotx_registration.domain import EncryptedSecret, SecretDecryptionError


class InMemoryDeliveryKeyProvider:
    """Libsodium delivery key held only in the process memory snapshot."""

    def __init__(self, private_key: PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> InMemoryDeliveryKeyProvider:
        return cls(PrivateKey.generate())

    async def public_key(self) -> bytes:
        return bytes(self._private_key.public_key)

    async def decrypt_sealed(self, ciphertext: bytes) -> bytes:
        try:
            return SealedBox(self._private_key).decrypt(ciphertext)
        except CryptoError as exc:
            raise SecretDecryptionError("sealed secret cannot be decrypted") from exc


class LocalKeyStore:
    """Persist key material in a bot-owned directory with Unix mode ``0600``.

    The directory must be a durable, access-restricted volume. PostgreSQL holds
    encrypted credentials; this store intentionally keeps their decryption
    material outside the database backup boundary.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def get_or_create(self, name: str, *, size: int) -> bytes:
        if not name or Path(name).name != name:
            raise ValueError("key name must be a plain file name")
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._directory, 0o700)
        key_path = self._directory / name
        lock_path = self._directory / f".{name}.lock"

        lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.chmod(lock_path, 0o600)
            with os.fdopen(lock_descriptor, "rb", closefd=False):
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
                if key_path.exists():
                    return self._read_key(key_path, size=size)
                key = os.urandom(size)
                self._write_key_atomically(key_path, key)
                return key
        finally:
            os.close(lock_descriptor)

    def _read_key(self, path: Path, *, size: int) -> bytes:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"key path is not a regular file: {path}")
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise PermissionError(
                f"key file must be owned by the bot and mode 0600: {path}"
            )
        key = path.read_bytes()
        if len(key) != size:
            raise ValueError(f"key file has an unexpected size: {path}")
        return key

    def _write_key_atomically(self, path: Path, key: bytes) -> None:
        descriptor, temporary_path = tempfile.mkstemp(
            dir=self._directory,
            prefix=f".{path.name}.",
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(key)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_path, path)
        except BaseException:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise


class LocalSecretBoxCipher:
    """Cipher configured from a key loaded by the durable-key bootstrap."""

    def __init__(self, key: bytes, *, key_id: str = "local-development") -> None:
        if len(key) != SecretBox.KEY_SIZE:
            raise ValueError(f"storage key must be {SecretBox.KEY_SIZE} bytes")
        self._box = SecretBox(key)
        self._key_id = key_id

    async def encrypt(self, plaintext: bytes) -> EncryptedSecret:
        return EncryptedSecret(
            ciphertext=bytes(self._box.encrypt(plaintext)), key_id=self._key_id
        )

    async def decrypt(self, encrypted: EncryptedSecret) -> bytes:
        if encrypted.key_id != self._key_id:
            raise SecretDecryptionError("unknown storage key id")
        try:
            return self._box.decrypt(encrypted.ciphertext)
        except CryptoError as exc:
            raise SecretDecryptionError("stored secret cannot be decrypted") from exc
