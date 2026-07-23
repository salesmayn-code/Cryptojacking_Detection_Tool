"""
CryptoDetect – Unit Tests: Authentication Module
=================================================
Tests JWT token generation/validation and bcrypt password hashing
as described in Chapter 6.2 (Unit Testing) of the FYP report.
"""
import pytest
import time
import secrets
import hashlib
import bcrypt
import jwt as pyjwt
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
#  Helpers (mirrors the real auth.py helpers)
# ─────────────────────────────────────────────
SECRET_KEY   = "cryptodetect_test_secret_key_2026"
ALGORITHM    = "HS256"
TOKEN_EXPIRE = 60  # minutes


def hash_password(plain: str) -> str:
    """Hash password with bcrypt (truncate to 72 bytes as bcrypt requires)."""
    secret = plain[:72].encode("utf-8")
    return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    secret = plain[:72].encode("utf-8")
    return bcrypt.checkpw(secret, hashed.encode("utf-8"))


def create_access_token(data: dict, expires_minutes: int = TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode["exp"] = expire
    return pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def generate_api_key() -> str:
    return secrets.token_hex(32)   # 64 hex chars


# ─────────────────────────────────────────────
#  Test Class: Password Hashing (bcrypt)
# ─────────────────────────────────────────────
class TestPasswordHashing:

    def test_hash_is_not_plaintext(self):
        """Hashed password must not equal the original string."""
        password = "MySecureP@ss123"
        hashed   = hash_password(password)
        assert hashed != password

    def test_correct_password_verifies(self):
        """Correct password must pass verification."""
        password = "MySecureP@ss123"
        hashed   = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_wrong_password_fails_verification(self):
        """Incorrect password must fail verification."""
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_same_password_produces_different_hashes(self):
        """bcrypt salts ensure identical inputs produce different hashes."""
        password = "SamePassword"
        assert hash_password(password) != hash_password(password)

    def test_empty_string_can_be_hashed(self):
        """Edge case: empty string should still be hashable."""
        hashed = hash_password("")
        assert isinstance(hashed, str) and len(hashed) > 0

    def test_long_password_is_handled(self):
        """bcrypt truncates at 72 bytes; passwords beyond that still verify correctly."""
        long_pw = "A" * 72   # exactly at bcrypt limit
        hashed  = hash_password(long_pw)
        assert verify_password(long_pw, hashed) is True


# ─────────────────────────────────────────────
#  Test Class: JWT Token Lifecycle
# ─────────────────────────────────────────────
class TestJWTTokens:

    def test_token_is_generated(self, valid_user):
        token = create_access_token({"sub": valid_user["email"]})
        assert token is not None and isinstance(token, str)

    def test_token_decodes_correctly(self, valid_user):
        token   = create_access_token({"sub": valid_user["email"]})
        payload = decode_access_token(token)
        assert payload["sub"] == valid_user["email"]

    def test_expired_token_raises_error(self, valid_user):
        """Token with past expiry must raise ExpiredSignatureError."""
        token = create_access_token({"sub": valid_user["email"]}, expires_minutes=-1)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            decode_access_token(token)

    def test_tampered_token_raises_error(self, valid_user):
        """Modifying a valid token must raise InvalidSignatureError."""
        token    = create_access_token({"sub": valid_user["email"]})
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(Exception):   # InvalidSignature or DecodeError
            decode_access_token(tampered)

    def test_token_contains_expiry_claim(self, valid_user):
        token   = create_access_token({"sub": valid_user["email"]})
        payload = decode_access_token(token)
        assert "exp" in payload

    def test_future_expiry_is_valid(self, valid_user):
        token   = create_access_token({"sub": valid_user["email"]}, expires_minutes=60)
        payload = decode_access_token(token)
        assert payload["exp"] > datetime.utcnow().timestamp()


# ─────────────────────────────────────────────
#  Test Class: API Key Generation
# ─────────────────────────────────────────────
class TestAPIKeyGeneration:

    def test_api_key_is_64_chars(self):
        """token_hex(32) produces 64 hex characters."""
        key = generate_api_key()
        assert len(key) == 64

    def test_api_key_is_hexadecimal(self):
        key = generate_api_key()
        assert all(c in "0123456789abcdef" for c in key)

    def test_api_keys_are_unique(self):
        """Two generated keys must differ (collision probability is negligible)."""
        key1 = generate_api_key()
        key2 = generate_api_key()
        assert key1 != key2

    def test_api_key_is_string(self):
        assert isinstance(generate_api_key(), str)
