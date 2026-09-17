import base64
import secrets
import threading
import uuid

import pytest

from src.otp_app.repository import (
    connect_database,
    create_schema,
    create_account_record,
    get_verification_state,
)

from src.otp_app.secret_store import (
    generate_storage_key,
    encrypt_account_secret,
)

from src.otp_app.service import verify_otp

from src.otp_app.totp_engine import TOTP


# ---------------------------------------------------------
# Test helpers
# ---------------------------------------------------------

def create_test_account(connection):
    """
    Create one encrypted test account with an initial
    verification-state record.
    """

    account_id = str(uuid.uuid4())
    account_name = "alice"

    # Project uses a 32-byte TOTP seed.
    seed = secrets.token_bytes(32)

    # Separate Fernet key used only for storage encryption.
    storage_key = generate_storage_key()

    ciphertext = encrypt_account_secret(
        storage_key,
        account_id,
        seed,
    )

    create_account_record(
        connection,
        account_id,
        account_name,
        ciphertext,
        1000,
    )

    return account_id, seed, storage_key


def generate_valid_otp(seed: bytes, timestamp: int) -> str:
    """
    Generate a valid project-configured TOTP for testing.

    Project configuration:
    - SHA-256
    - 6 digits
    - 30-second period
    """

    base32_secret = base64.b32encode(seed).decode("ascii")

    return TOTP(
        secret=base32_secret,
        digits=6,
        period=30,
        algorithm="sha256",
    ).generate(timestamp)


def make_wrong_otp(valid_otp: str) -> str:
    """
    Produce a guaranteed different six-digit OTP.
    """

    if valid_otp != "000000":
        return "000000"

    return "111111"


# ---------------------------------------------------------
# 1. Valid OTP succeeds
# ---------------------------------------------------------

def test_valid_otp_succeeds(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    result = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert result.success is True
    assert result.outcome == "success"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    # 1200 // 30 = 40
    assert state[0] == now // 30

    # Successful verification clears failure state.
    assert state[1] == 0
    assert state[2] == 0

    connection.close()


# ---------------------------------------------------------
# 2. Replay prevention
# ---------------------------------------------------------

def test_successful_otp_cannot_be_replayed(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    first = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert first.success is True
    assert first.outcome == "success"

    # Submit the same OTP for the same time counter.
    second = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert second.success is False
    assert second.outcome == "replay"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    # Accepted counter remains stored.
    assert state[0] == now // 30

    # Replay counts as one failed attempt.
    assert state[1] == 1

    connection.close()


# ---------------------------------------------------------
# 3. Wrong OTP increments failure count
# ---------------------------------------------------------

def test_wrong_otp_increments_failure_count(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    wrong_otp = make_wrong_otp(valid_otp)

    result = verify_otp(
        connection,
        storage_key,
        account_id,
        wrong_otp,
        now=now,
    )

    assert result.success is False
    assert result.outcome == "no_match"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    assert state[0] == -1
    assert state[1] == 1
    assert state[2] == 0

    connection.close()


# ---------------------------------------------------------
# 4. Five failures start 60-second cooldown
# ---------------------------------------------------------

def test_five_failures_start_cooldown(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    wrong_otp = make_wrong_otp(valid_otp)

    result = None

    for _ in range(5):
        result = verify_otp(
            connection,
            storage_key,
            account_id,
            wrong_otp,
            now=now,
        )

    assert result is not None

    assert result.success is False
    assert result.outcome == "cooldown_started"
    assert result.locked_until == now + 60

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    assert state[1] == 5
    assert state[2] == 1260

    connection.close()


# ---------------------------------------------------------
# 5. Valid OTP is blocked during cooldown
# ---------------------------------------------------------

def test_valid_otp_is_blocked_during_cooldown(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    start_time = 1200

    valid_otp = generate_valid_otp(
        seed,
        start_time,
    )

    wrong_otp = make_wrong_otp(valid_otp)

    # Trigger cooldown.
    for _ in range(5):
        verify_otp(
            connection,
            storage_key,
            account_id,
            wrong_otp,
            now=start_time,
        )

    # Cooldown lasts until 1260.
    attempt_time = 1230

    valid_during_cooldown = generate_valid_otp(
        seed,
        attempt_time,
    )

    result = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_during_cooldown,
        now=attempt_time,
    )

    assert result.success is False
    assert result.outcome == "throttled"
    assert result.locked_until == 1260

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    # Throttled requests do not increase failures
    # or extend the cooldown.
    assert state[1] == 5
    assert state[2] == 1260

    connection.close()


# ---------------------------------------------------------
# 6. Cooldown expiry allows verification again
# ---------------------------------------------------------

def test_verification_allowed_after_cooldown_expires(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    start_time = 1200

    initial_valid_otp = generate_valid_otp(
        seed,
        start_time,
    )

    wrong_otp = make_wrong_otp(
        initial_valid_otp
    )

    for _ in range(5):
        verify_otp(
            connection,
            storage_key,
            account_id,
            wrong_otp,
            now=start_time,
        )

    # Cooldown expires exactly at timestamp 1260.
    new_time = 1260

    new_valid_otp = generate_valid_otp(
        seed,
        new_time,
    )

    result = verify_otp(
        connection,
        storage_key,
        account_id,
        new_valid_otp,
        now=new_time,
    )

    assert result.success is True
    assert result.outcome == "success"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    assert state[0] == new_time // 30
    assert state[1] == 0
    assert state[2] == 0

    connection.close()


# ---------------------------------------------------------
# 7. Malformed OTP counts as a failed attempt
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "invalid_otp",
    [
        "12345",
        "1234567",
        "abcdef",
        "12 456",
        "１２３４５６",
    ],
)
def test_malformed_otp_counts_as_failure(
    tmp_path,
    invalid_otp,
):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    result = verify_otp(
        connection,
        storage_key,
        account_id,
        invalid_otp,
        now=1200,
    )

    assert result.success is False
    assert result.outcome == "invalid_input"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None
    assert state[1] == 1

    connection.close()


# ---------------------------------------------------------
# 8. Success clears previous failed attempts
# ---------------------------------------------------------

def test_success_clears_previous_failures(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    wrong_otp = make_wrong_otp(
        valid_otp
    )

    # Two failed attempts.
    verify_otp(
        connection,
        storage_key,
        account_id,
        wrong_otp,
        now=now,
    )

    verify_otp(
        connection,
        storage_key,
        account_id,
        wrong_otp,
        now=now,
    )

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state[1] == 2

    # Correct OTP should succeed and reset failures.
    result = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert result.success is True

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state[1] == 0
    assert state[2] == 0

    connection.close()


# ---------------------------------------------------------
# 9. Failure state survives database restart
# ---------------------------------------------------------

def test_failure_state_survives_restart(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    wrong_otp = make_wrong_otp(
        valid_otp
    )

    # Three failed attempts.
    for _ in range(3):
        verify_otp(
            connection,
            storage_key,
            account_id,
            wrong_otp,
            now=now,
        )

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state[1] == 3

    # Simulate closing the application.
    connection.close()

    # Simulate application restart.
    connection = connect_database(
        database_path
    )

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None

    # Failure state must remain persistent.
    assert state[1] == 3

    connection.close()


# ---------------------------------------------------------
# 10. Replay state survives database restart
# ---------------------------------------------------------

def test_replay_state_survives_restart(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)
    create_schema(connection)

    account_id, seed, storage_key = create_test_account(
        connection
    )

    now = 1200

    valid_otp = generate_valid_otp(
        seed,
        now,
    )

    first = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert first.success is True

    connection.close()

    # Reopen the same database.
    connection = connect_database(
        database_path
    )

    second = verify_otp(
        connection,
        storage_key,
        account_id,
        valid_otp,
        now=now,
    )

    assert second.success is False
    assert second.outcome == "replay"

    state = get_verification_state(
        connection,
        account_id,
    )

    assert state is not None
    assert state[0] == now // 30

    connection.close()


def test_concurrent_duplicate_otp_only_one_succeeds(tmp_path):
    database_path = tmp_path / "test.sqlite3"

    setup_connection = connect_database(database_path)
    create_schema(setup_connection)

    account_id, seed, storage_key = create_test_account(setup_connection)
    setup_connection.close()

    now = 1200
    valid_otp = generate_valid_otp(seed, now)
    results = []
    errors = []

    def worker():
        connection = connect_database(database_path)
        try:
            result = verify_otp(
                connection,
                storage_key,
                account_id,
                valid_otp,
                now=now,
            )
            results.append(result)
        except Exception as exc:
            errors.append(exc)
        finally:
            connection.close()

    thread1 = threading.Thread(target=worker)
    thread2 = threading.Thread(target=worker)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

    assert errors == []
    assert len(results) == 2

    successful = [result for result in results if result.success]
    rejected = [result for result in results if not result.success]

    assert len(successful) == 1
    assert len(rejected) == 1
    assert successful[0].outcome == "success"
    assert rejected[0].outcome == "replay"