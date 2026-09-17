import secrets
import time
import uuid

from src.otp_app.repository import (
    connect_database,
    create_schema,
    create_account_record,
    get_account,
)

from src.otp_app.secret_store import (
    generate_storage_key,
    encrypt_account_secret,
    decrypt_account_secret,
)


def test_encrypted_secret_database_round_trip(tmp_path):

    database_path = tmp_path / "test.sqlite3"

    connection = connect_database(database_path)

    try:
        create_schema(connection)
        account_id = str(uuid.uuid4())

        account_name = "alice"

        seed = secrets.token_bytes(32)

        storage_key = generate_storage_key()

        created_at = int(time.time())
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
            created_at,
        )
        row = get_account(
            connection,
            account_id,
        )

        assert row is not None
        stored_ciphertext = row[2]
        recovered_seed = decrypt_account_secret(
            storage_key,
            account_id,
            stored_ciphertext,
        )
        assert recovered_seed == seed
        assert seed != stored_ciphertext
        state = connection.execute(
            """
            SELECT
                last_accepted_counter,
                failed_attempts,
                locked_until
            FROM verification_state
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()
        assert state is not None

        assert state[0] == -1
        assert state[1] == 0
        assert state[2] == 0
    finally:
        connection.close()
