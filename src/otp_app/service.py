import base64
import hmac
import time
from dataclasses import dataclass

from .config import (
    COOLDOWN_SECONDS,
    MAX_FAILED_ATTEMPTS,
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_PERIOD,
)
from .repository import (
    get_account,
    get_verification_state,
    insert_audit_event,
    update_verification_state,
)
from .secret_store import decrypt_account_secret
from .totp_engine import TOTP


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
