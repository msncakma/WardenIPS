"""Authentication helpers for dashboard bootstrap, passwords, and TOTP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import qrcode


_PASSWORD_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash an operator password using Argon2id."""
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, candidate: str) -> bool:
    """Verify an operator password against an Argon2id hash."""
    try:
        return _PASSWORD_HASHER.verify(password_hash, candidate)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def hash_bootstrap_token(token: str) -> str:
    """Hash a bootstrap token for safe storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_bootstrap_token(expected_hash: str, candidate: str) -> bool:
    """Verify a bootstrap token against its SHA-256 digest."""
    actual = hash_bootstrap_token(candidate)
    return hmac.compare_digest(expected_hash, actual)


def generate_totp_secret() -> str:
    """Return a new TOTP seed."""
    return pyotp.random_base32()


def build_totp_uri(username: str, secret: str, issuer: str = "WardenIPS") -> str:
    """Build an otpauth:// provisioning URI."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a TOTP code with a small clock-skew window."""
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=valid_window)


def build_totp_qr_data_url(uri: str) -> str:
    """Render a QR code to a data URL for inline setup pages."""
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def check_password_policy(password: str) -> tuple[bool, str]:
    """Validate baseline operator password requirements."""
    if len(password) < 14:
        return False, "Password must be at least 14 characters long."
    if password.lower() == password or password.upper() == password:
        return False, "Password must include both uppercase and lowercase letters."
    if not any(character.isdigit() for character in password):
        return False, "Password must include at least one digit."
    if not any(not character.isalnum() for character in password):
        return False, "Password must include at least one symbol."
    return True, "ok"


def sanitize_release_preview(lines: list[str] | None) -> list[str]:
    """Return short, safe release notes for dashboards and docs."""
    cleaned: list[str] = []
    for line in lines or []:
      value = str(line).strip()
      if value:
        cleaned.append(value[:220])
    return cleaned