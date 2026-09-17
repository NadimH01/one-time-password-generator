import base64
import hmac
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass

from .config import (
    COOLDOWN_SECONDS,
    MAX_FAILED_ATTEMPTS,
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_PERIOD,
)
from .repository import (
    create_account_record,
    get_account,
    get_verification_state,
    insert_audit_event,
    list_accounts,
    update_verification_state,
)
from .secret_store import (
    decrypt_account_secret,
    encrypt_account_secret,
)
from .totp_engine import TOTP


ACCOUNT_NAME_PATTERN = re.compile(
    r"^[a-z0-9_.-]{3,32}$"
)


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    outcome: str
    locked_until: int = 0


def is_valid_otp_format(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == TOTP_DIGITS
        and value.isascii()
        and value.isdigit()
    )


def normalise_account_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("Account name must be text.")

    return value.strip().lower()


def validate_account_name(value: str) -> str:
    name = normalise_account_name(value)

    if not ACCOUNT_NAME_PATTERN.fullmatch(name):
        raise ValueError(
            "Account name must contain 3-32 letters, digits, "
            "underscores, hyphens, or periods."
        )

    return name


def get_account_choices(connection):
    rows = list_accounts(connection)

    return [
        {
            "account_id": row[0],
            "account_name": row[1],
        }
        for row in rows
    ]


def enrol_account(
    connection,
    storage_key: bytes,
    account_name: str,
    now: int | None = None,
) -> str:
    if now is None:
        now = int(time.time())

    canonical_name = validate_account_name(account_name)
    account_id = str(uuid.uuid4())
    seed = secrets.token_bytes(32)
    ciphertext = encrypt_account_secret(
        storage_key,
        account_id,
        seed,
    )

    try:
        create_account_record(
            connection,
            account_id,
            canonical_name,
            ciphertext,
            now,
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(
            "An account with that name already exists."
        ) from exc

    return account_id


def generate_current_otp(
    connection,
    storage_key: bytes,
    account_id: str,
    now: int | None = None,
):
    if now is None:
        now = int(time.time())

    account = get_account(connection, account_id)
    if account is None:
        raise ValueError("Account does not exist.")

    ciphertext = account[2]
    seed = decrypt_account_secret(
        storage_key,
        account_id,
        ciphertext,
    )
    base32_secret = base64.b32encode(seed).decode("ascii")
    otp = TOTP(
        secret=base32_secret,
        digits=TOTP_DIGITS,
        period=TOTP_PERIOD,
        algorithm=TOTP_ALGORITHM,
    ).generate(now)
    remaining = TOTP_PERIOD - (now % TOTP_PERIOD)

    return {
        "otp": otp,
        "remaining": remaining,
        "counter": now // TOTP_PERIOD,
    }


def verify_otp(
    connection,
    storage_key: bytes,
    account_id: str,
    supplied_otp: str,
    now: int | None = None,
) -> VerificationResult:
    if now is None:
        now = int(time.time())

    connection.execute("BEGIN IMMEDIATE")

    try:
        account = get_account(connection, account_id)
        if account is None:
            raise ValueError("Account does not exist.")

        state = get_verification_state(connection, account_id)
        if state is None:
            raise RuntimeError("Verification state is missing.")

        last_accepted_counter = state[0]
        failed_attempts = state[1]
        locked_until = state[2]

        if locked_until > now:
            insert_audit_event(connection, now, account_id, "verification", "throttled")
            connection.commit()
            return VerificationResult(
                success=False,
                outcome="throttled",
                locked_until=locked_until,
            )

        if locked_until != 0 and locked_until <= now:
            failed_attempts = 0
            locked_until = 0

        if not is_valid_otp_format(supplied_otp):
            failed_attempts += 1
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                failed_attempts = MAX_FAILED_ATTEMPTS
                locked_until = now + COOLDOWN_SECONDS
                outcome = "cooldown_started"
            else:
                outcome = "invalid_input"

            update_verification_state(
                connection,
                account_id,
                last_accepted_counter,
                failed_attempts,
                locked_until,
            )
            insert_audit_event(connection, now, account_id, "verification", outcome)
            connection.commit()
            return VerificationResult(
                success=False,
                outcome=outcome,
                locked_until=locked_until,
            )

        ciphertext = account[2]
        seed = decrypt_account_secret(storage_key, account_id, ciphertext)
        base32_secret = base64.b32encode(seed).decode("ascii")
        expected_otp = TOTP(
            secret=base32_secret,
            digits=TOTP_DIGITS,
            period=TOTP_PERIOD,
            algorithm=TOTP_ALGORITHM,
        ).generate(now)
        matches = hmac.compare_digest(supplied_otp, expected_otp)
        current_counter = now // TOTP_PERIOD

        if matches and current_counter > last_accepted_counter:
            update_verification_state(
                connection,
                account_id,
                current_counter,
                0,
                0,
            )
            insert_audit_event(connection, now, account_id, "verification", "success")
            connection.commit()
            return VerificationResult(success=True, outcome="success")

        outcome = "replay" if matches else "no_match"
        failed_attempts += 1
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            failed_attempts = MAX_FAILED_ATTEMPTS
            locked_until = now + COOLDOWN_SECONDS
            outcome = "cooldown_started"

        update_verification_state(
            connection,
            account_id,
            last_accepted_counter,
            failed_attempts,
            locked_until,
        )
        insert_audit_event(connection, now, account_id, "verification", outcome)
        connection.commit()
        return VerificationResult(
            success=False,
            outcome=outcome,
            locked_until=locked_until,
        )
    except Exception:
        connection.rollback()
        raise
