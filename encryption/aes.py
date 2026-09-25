"""AES-256-GCM encryption for PII fields (PAN, account numbers, Aadhaar) before DB write."""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

_NONCE_SIZE = 12


def _get_key() -> bytes:
    """Load the 32-byte AES key from the AES_KEY environment variable."""
    key_hex = os.getenv("AES_KEY")
    if not key_hex:
        raise RuntimeError("AES_KEY is not set in the environment")
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise RuntimeError("AES_KEY must decode to exactly 32 bytes for AES-256")
    return key


def encrypt(plaintext: str) -> str:
    """Encrypt plaintext with AES-256-GCM, returning a base64 nonce+ciphertext string."""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64 nonce+ciphertext string produced by encrypt() back to plaintext."""
    key = _get_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(ciphertext)
    nonce, actual_ciphertext = raw[:_NONCE_SIZE], raw[_NONCE_SIZE:]
    plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
    return plaintext.decode("utf-8")
