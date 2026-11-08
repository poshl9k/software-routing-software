"""Encrypt Telegram API tokens at rest; never return them from settings reads."""
from vs_router.schema import EncryptedSecret
from vs_router.secrets import decrypt_secret, encrypt_secret

PREFIX = 'enc:'

def encode_bot_token(token: str, key: bytes) -> str:
    return PREFIX + encrypt_secret(token, key).ciphertext

def decode_bot_token(value: str, key: bytes) -> str:
    if value.startswith(PREFIX):
        return decrypt_secret(EncryptedSecret(ciphertext=value[len(PREFIX):]), key)
    # Existing installations may still hold a plaintext token. Migrate on read.
    return value
