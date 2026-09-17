import base64
import json
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import (
    ACCOUNT_SECRET_LENGTH,
    PAYLOAD_VERSION,
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_PERIOD,
)


def generate_storage_key() -> bytes:
    return Fernet.generate_key()


def save_storage_key(
    key_path: Path,
    key: bytes,
) -> None:
    key_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if key_path.exists():
        raise FileExistsError(
            "Storage key already exists."
        )

    key_path.write_bytes(key)


def load_storage_key(
    key_path: Path,
) -> bytes:
    if not key_path.exists():
        raise FileNotFoundError(
            "Storage key is missing."
        )

    key = key_path.read_bytes()

    try:
        Fernet(key)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "Storage key is invalid."
        ) from exc

    return key


def encrypt_account_secret(
    key: bytes,
    account_id: str,
    seed: bytes,
) -> bytes:

    if not account_id:
        raise ValueError("Account ID cannot be empty.")

    if not isinstance(seed, bytes):
        raise TypeError("Seed must be bytes.")

    if len(seed) != ACCOUNT_SECRET_LENGTH:
        raise ValueError(
            f"Seed must be {ACCOUNT_SECRET_LENGTH} bytes."
        )

    payload = {
        "version": PAYLOAD_VERSION,
        "account_id": account_id,
        "algorithm": TOTP_ALGORITHM,
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
        "seed": base64.b64encode(seed).decode("ascii"),
    }

    plaintext = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    fernet = Fernet(key)

    return fernet.encrypt(plaintext)


def decrypt_account_secret(
    key: bytes,
    expected_account_id: str,
    ciphertext: bytes,
) -> bytes:

    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError(
            "Protected account data could not be authenticated."
        ) from exc

    try:
        payload = json.loads(
            plaintext.decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Protected account payload is invalid."
        ) from exc

    if payload.get("version") != PAYLOAD_VERSION:
        raise ValueError("Unsupported payload version.")

    if payload.get("account_id") != expected_account_id:
        raise ValueError("Account binding mismatch.")

    if payload.get("algorithm") != TOTP_ALGORITHM:
        raise ValueError("Unexpected TOTP algorithm.")

    if payload.get("digits") != TOTP_DIGITS:
        raise ValueError("Unexpected TOTP digit configuration.")

    if payload.get("period") != TOTP_PERIOD:
        raise ValueError("Unexpected TOTP period.")

    try:
        seed = base64.b64decode(
            payload["seed"],
            validate=True,
        )
    except (KeyError, ValueError) as exc:
        raise ValueError(
            "Protected seed is invalid."
        ) from exc

    if len(seed) != ACCOUNT_SECRET_LENGTH:
        raise ValueError(
            "Protected seed has an invalid length."
        )

    return seed