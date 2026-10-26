"""
Tests for credential encryption, decryption, and masking.
"""

import pytest

from services.crypto import CredentialCrypto, CryptoError, mask_credential


class TestCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        crypto = CredentialCrypto("test-master-encryption-key-12345")
        secret = "md5d_live_my_super_secret_api_key_abc123"

        token = crypto.encrypt(secret)
        assert token.startswith("enc:v1:")
        assert secret not in token

        decrypted = crypto.decrypt(token)
        assert decrypted == secret

    def test_decrypt_with_different_key_fails(self):
        crypto1 = CredentialCrypto("key-one-12345678901234567890")
        crypto2 = CredentialCrypto("key-two-98765432109876543210")

        token = crypto1.encrypt("my_secret")
        with pytest.raises(CryptoError):
            crypto2.decrypt(token)

    def test_tampered_token_fails(self):
        crypto = CredentialCrypto("test-master-encryption-key-12345")
        token = crypto.encrypt("my_secret")

        # Corrupt one character in the base64 payload
        prefix = "enc:v1:"
        body = token[len(prefix):]
        corrupted_body = ("B" if body[0] == "A" else "A") + body[1:]
        corrupted_token = prefix + corrupted_body

        with pytest.raises(CryptoError):
            crypto.decrypt(corrupted_token)

    def test_empty_strings(self):
        crypto = CredentialCrypto("test-master-encryption-key-12345")
        assert crypto.encrypt("") == ""
        assert crypto.decrypt("") == ""

    def test_mask_credential(self):
        assert mask_credential("md5d_live_155f0730_phEgWCGkD_dYIFpqOeeXCQa-K2Y7xBOAa_CzKxmzDqY") == "********zDqY"
        assert mask_credential("secret1234") == "********1234"
        assert mask_credential("short") == "********"
        assert mask_credential("") == "********"
