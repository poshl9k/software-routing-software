"""Authenticated encryption with a caller-owned key; keys never enter snapshots."""
from cryptography.fernet import Fernet
from .schema import EncryptedSecret


def encrypt_secret(plaintext: str, key: bytes) -> EncryptedSecret:
    return EncryptedSecret(ciphertext=Fernet(key).encrypt(plaintext.encode()).decode())


def decrypt_secret(secret: EncryptedSecret, key: bytes) -> str:
    return Fernet(key).decrypt(secret.ciphertext.encode()).decode()
