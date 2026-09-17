"""RFC 4226 HOTP and RFC 6238 TOTP implementation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from collections.abc import Callable
from typing import Final

DEFAULT_DIGITS: Final = 6
DEFAULT_PERIOD: Final = 30
_ALLOWED_DIGITS: Final = frozenset({6, 7, 8})
_ALLOWED_ALGORITHMS: Final = frozenset({"sha1", "sha256", "sha512"})


def generate_secret(length: int = 20) -> str:
    """Return a random secret encoded as unpadded Base32 text."""
    if length <= 0:
        raise ValueError("length must be positive")
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    normalized = "".join(secret.split()).upper()
    if not normalized:
        raise ValueError("secret must not be empty")
    padding = "=" * (-len(normalized) % 8)
    try:
        return base64.b32decode(normalized + padding, casefold=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("secret must be valid Base32") from error


def _validate_options(digits: int, algorithm: str) -> str:
    if digits not in _ALLOWED_DIGITS:
        raise ValueError("digits must be 6, 7, or 8")
    normalized_algorithm = algorithm.lower()
    if normalized_algorithm not in _ALLOWED_ALGORITHMS:
        raise ValueError("algorithm must be SHA1, SHA256, or SHA512")
    return normalized_algorithm


def _hotp(secret: bytes, counter: int, digits: int, algorithm: str) -> str:
    if counter < 0:
        raise ValueError("counter must not be negative")
    digest = hmac.new(secret, struct.pack(">Q", counter), getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % (10**digits)
    return f"{code:0{digits}d}"


class HOTP:
    """Generate counter-based one-time passwords."""

    def __init__(self, secret: str, digits: int = DEFAULT_DIGITS, algorithm: str = "SHA1") -> None:
        self._secret = _decode_secret(secret)
        self.digits = digits
        self.algorithm = _validate_options(digits, algorithm)

    def generate(self, counter: int) -> str:
        """Generate a password for an unsigned 64-bit counter."""
        if counter > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("counter exceeds the unsigned 64-bit range")
        return _hotp(self._secret, counter, self.digits, self.algorithm)


class TOTP(HOTP):
    """Generate time-based one-time passwords."""

    def __init__(
        self,
        secret: str,
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
        algorithm: str = "SHA1",
        time_provider: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(secret, digits, algorithm)
        if period <= 0:
            raise ValueError("period must be positive")
        self.period = period
        self._time_provider = time_provider

    def generate(self, timestamp: float | None = None) -> str:
        """Generate a password for a Unix timestamp, or the current time."""
        current_time = self._time_provider() if timestamp is None else timestamp
        if current_time < 0:
            raise ValueError("timestamp must not be negative")
        return super().generate(int(current_time) // self.period)

    def remaining_seconds(self, timestamp: float | None = None) -> int:
        """Return whole seconds remaining in the current time window."""
        current_time = self._time_provider() if timestamp is None else timestamp
        if current_time < 0:
            raise ValueError("timestamp must not be negative")
        return self.period - (int(current_time) % self.period)
