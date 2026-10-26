"""
Credential encryption and masking module for Student Credentials Provider.

Encrypts sensitive API credentials at rest using authenticated encryption
(HMAC-SHA256 authenticated CTR keystream) without external C dependencies,
and masks credentials for safe presentation in administrative interfaces.
"""

import base64
import hashlib
import hmac
import os
import secrets


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""
    pass


class CredentialCrypto:
    """Manages authenticated encryption/decryption of API credentials."""

    def __init__(self, secret_key: str | None = None):
        raw_key = secret_key or os.getenv("API_ENCRYPTION_KEY", "scp-encryption-secret-key-32chars!")
        self.secret_key = raw_key.encode("utf-8")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext credential string into an authenticated token.

        Format: enc:v1:<base64(16-byte nonce + 32-byte HMAC + ciphertext)>
        """
        if not plaintext:
            return ""

        try:
            data = plaintext.encode("utf-8")
            nonce = secrets.token_bytes(16)

            # Derive domain-separated subkeys
            enc_key = hashlib.sha256(self.secret_key + b":enc").digest()
            mac_key = hashlib.sha256(self.secret_key + b":mac").digest()

            # Generate keystream block-by-block
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(data):
                block = hashlib.sha256(enc_key + nonce + counter.to_bytes(4, "big")).digest()
                keystream.extend(block)
                counter += 1

            ciphertext = bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))
            tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
            payload = nonce + tag + ciphertext

            return "enc:v1:" + base64.urlsafe_b64encode(payload).decode("ascii")
        except Exception as exc:
            raise CryptoError(f"Encryption failed: {exc}") from exc

    def decrypt(self, token: str) -> str:
        """
        Decrypt an authenticated token back to the original plaintext credential.
        """
        if not token:
            return ""

        if not token.startswith("enc:v1:"):
            raise CryptoError("Invalid or unsupported ciphertext token format.")

        try:
            raw = base64.urlsafe_b64decode(token[7:].encode("ascii"))
            if len(raw) < 48:
                raise CryptoError("Ciphertext payload is too short.")

            nonce, tag, ciphertext = raw[:16], raw[16:48], raw[48:]

            mac_key = hashlib.sha256(self.secret_key + b":mac").digest()
            expected_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()

            if not hmac.compare_digest(tag, expected_tag):
                raise CryptoError("Authentication tag verification failed. Data corrupted or key mismatch.")

            enc_key = hashlib.sha256(self.secret_key + b":enc").digest()
            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ciphertext):
                block = hashlib.sha256(enc_key + nonce + counter.to_bytes(4, "big")).digest()
                keystream.extend(block)
                counter += 1

            data = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
            return data.decode("utf-8")
        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(f"Decryption failed: {exc}") from exc


def mask_credential(credential: str) -> str:
    """
    Mask a sensitive API key for safe display in administrative interfaces.

    Shows only the last 4 characters if long enough, e.g. '********abcd'.
    Never returns full secret.
    """
    if not credential:
        return "********"

    clean = str(credential).strip()
    if len(clean) <= 6:
        return "********"

    last_chars = clean[-4:]
    return f"********{last_chars}"
