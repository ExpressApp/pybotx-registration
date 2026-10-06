from __future__ import annotations

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox
from nacl.secret import SecretBox

from pybotx_registration.domain import EncryptedSecret, SecretDecryptionError


class InMemoryDeliveryKeyProvider:
    """Libsodium delivery key. Inject a KMS-backed implementation in production."""

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


class LocalSecretBoxCipher:
    """Development-only at-rest cipher; use an envelope KMS/Vault adapter in prod."""

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
